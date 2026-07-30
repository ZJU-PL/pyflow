"""Built-in and declarative adapters for benchmark analyzers."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .process import ProcessOutcome, probe_version, run_process


PYFLOW_ENGINES = {
    "pyflow-ast-scanner": "ast-scanner",
    "pyflow-ast-dataflow": "ast-dataflow",
    "pyflow-ifds": "ifds",
    "pyflow-cpg": "cpg",
}
BUILTIN_ENGINES = tuple(PYFLOW_ENGINES) + ("codeql", "pysa", "bandit")


@dataclass(frozen=True)
class AdapterContext:
    engine: str
    sample_id: str
    target: Path
    run_dir: Path
    timeout_seconds: float
    sample_args: tuple[str, ...] = ()
    config: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterResult:
    status: str
    commands: tuple[ProcessOutcome, ...]
    tool_version: str | None
    raw_output: str | None = None
    finding_count: int | None = None
    analysis_status: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    error: str | None = None


class EngineAdapter:
    name: str

    def run(self, context: AdapterContext) -> AdapterResult:
        raise NotImplementedError


class CommandAdapter(EngineAdapter):
    """Execute a config-defined analyzer without loading analyzer-specific code."""

    def __init__(self, name: str):
        self.name = name

    def run(self, context: AdapterContext) -> AdapterResult:
        steps = context.config.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError("command adapter 'steps' must be a non-empty list")
        report_config = _mapping(context.config.get("report", {}), "report")
        report = _report_path(context, report_config)
        variables = {
            "engine": context.engine,
            "sample_id": context.sample_id,
            "target": str(context.target),
            "run_dir": str(context.run_dir),
            "report": str(report) if report is not None else "",
        }
        version_argv = context.config.get("version_argv")
        version = None
        if version_argv is not None:
            version_env = _string_mapping(
                context.config.get("version_env", {}), "version_env"
            )
            version_env = {
                key: _expand(value, variables) for key, value in version_env.items()
            }
            version = probe_version(
                _expand_argv(version_argv, variables, (), "version_argv"),
                cwd=context.run_dir,
                env=version_env,
            )

        commands: list[ProcessOutcome] = []
        step_names: set[str] = set()
        for index, raw_step in enumerate(steps):
            step = _mapping(raw_step, f"steps[{index}]")
            name = step.get("name", f"step-{index + 1}")
            if not isinstance(name, str) or not name or "/" in name or "\\" in name:
                raise ValueError(f"steps[{index}].name must be a safe non-empty string")
            if name in step_names:
                raise ValueError(f"duplicate command step name: {name!r}")
            step_names.add(name)
            argv = _expand_argv(
                step.get("argv"), variables, context.sample_args, f"steps[{index}].argv"
            )
            accepted = _returncodes(step.get("accepted_returncodes", [0]), index)
            timeout = _positive_number(
                step.get("timeout_seconds", context.timeout_seconds),
                f"steps[{index}].timeout_seconds",
            )
            cwd_name = step.get("cwd", "run_dir")
            if cwd_name not in {"run_dir", "target"}:
                raise ValueError(f"steps[{index}].cwd must be 'run_dir' or 'target'")
            cwd = context.run_dir if cwd_name == "run_dir" else context.target
            env = _string_mapping(step.get("env", {}), f"steps[{index}].env")
            env = {key: _expand(value, variables) for key, value in env.items()}
            outcome = run_process(
                argv,
                cwd=cwd,
                timeout_seconds=timeout,
                stdout_path=context.run_dir / f"{name}.stdout.log",
                stderr_path=context.run_dir / f"{name}.stderr.log",
                env=env,
            )
            commands.append(outcome)
            if outcome.timed_out:
                return AdapterResult(
                    status="timed_out",
                    commands=tuple(commands),
                    tool_version=version,
                    error=f"step {name!r} timed out",
                )
            if outcome.error or outcome.returncode not in accepted:
                return AdapterResult(
                    status="unavailable" if outcome.error else "failed",
                    commands=tuple(commands),
                    tool_version=version,
                    error=outcome.error or f"step {name!r} exited {outcome.returncode}",
                )

        try:
            finding_count, analysis_status = _read_declarative_report(
                report, report_config
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return AdapterResult(
                status="failed",
                commands=tuple(commands),
                tool_version=version,
                error=f"invalid report: {exc}",
            )
        status = "partial" if analysis_status == "partial" else "complete"
        if analysis_status in {"failed", "invalid"}:
            status = "failed"
        return AdapterResult(
            status=status,
            commands=tuple(commands),
            tool_version=version,
            raw_output=(
                str(report.relative_to(context.run_dir))
                if report and report_config.get("format", "json") != "none"
                else None
            ),
            finding_count=finding_count,
            analysis_status=analysis_status,
        )


class PyFlowAdapter(EngineAdapter):
    def __init__(self, name: str, security_engine: str):
        self.name = name
        self.security_engine = security_engine

    def run(self, context: AdapterContext) -> AdapterResult:
        command = _command(
            context.config,
            default=(sys.executable, "-m", "pyflow.cli.main"),
        )
        raw = context.run_dir / "report.json"
        argv = [
            *command,
            "security",
            str(context.target),
            "--engine",
            self.security_engine,
            "--recursive",
            "--format",
            "json",
            "--output",
            str(raw),
            "--exit-code-policy",
            "report",
            *_string_list(context.config.get("args", []), "args"),
            *context.sample_args,
        ]
        outcome = _run(context, argv, "analyze")
        version = probe_version([*command, "--version"], cwd=context.run_dir)
        if outcome.timed_out:
            return _result("timed_out", outcome, version, error="analysis timed out")
        if outcome.error or outcome.returncode != 0:
            return _result(
                "unavailable" if outcome.error else "failed",
                outcome,
                version,
                error=outcome.error or f"exit status {outcome.returncode}",
            )
        try:
            payload = json.loads(raw.read_text(encoding="utf-8"))
            findings = payload.get("results", payload.get("findings", []))
            finding_count = len(findings) if isinstance(findings, list) else None
            analysis_status = payload.get("status")
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            return _result("failed", outcome, version, error=f"invalid report: {exc}")
        status = (
            analysis_status
            if analysis_status
            in {"complete", "partial", "cancelled", "failed", "invalid"}
            else "complete"
        )
        return AdapterResult(
            status=status,
            commands=(outcome,),
            tool_version=version,
            raw_output=raw.name,
            finding_count=finding_count,
            analysis_status=analysis_status,
        )


class BanditAdapter(EngineAdapter):
    name = "bandit"

    def run(self, context: AdapterContext) -> AdapterResult:
        command = _command(context.config, default=("bandit",))
        raw = context.run_dir / "report.json"
        argv = [
            *command,
            "-r",
            str(context.target),
            "-f",
            "json",
            "-o",
            str(raw),
            *_string_list(context.config.get("args", []), "args"),
            *context.sample_args,
        ]
        outcome = _run(context, argv, "analyze")
        version = probe_version([*command, "--version"], cwd=context.run_dir)
        if outcome.timed_out:
            return _result("timed_out", outcome, version, error="analysis timed out")
        if outcome.error or outcome.returncode not in {0, 1}:
            return _result(
                "unavailable" if outcome.error else "failed",
                outcome,
                version,
                error=outcome.error or f"exit status {outcome.returncode}",
            )
        try:
            payload = json.loads(raw.read_text(encoding="utf-8"))
            findings = payload.get("results", [])
            finding_count = len(findings) if isinstance(findings, list) else None
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            return _result("failed", outcome, version, error=f"invalid report: {exc}")
        return AdapterResult(
            status="complete",
            commands=(outcome,),
            tool_version=version,
            raw_output=raw.name,
            finding_count=finding_count,
        )


class CodeQLAdapter(EngineAdapter):
    name = "codeql"

    def run(self, context: AdapterContext) -> AdapterResult:
        command = _command(context.config, default=("codeql",))
        version = probe_version(
            [*command, "version", "--format=terse"], cwd=context.run_dir
        )
        database = context.run_dir / "database"
        raw = context.run_dir / "report.sarif"
        create_argv = [
            *command,
            "database",
            "create",
            str(database),
            "--source-root",
            str(context.target),
            "--language=python",
            *_string_list(context.config.get("create_args", []), "create_args"),
        ]
        create = _run(context, create_argv, "database-create")
        if create.timed_out:
            return _result(
                "timed_out", create, version, error="database creation timed out"
            )
        if create.error or create.returncode != 0:
            return _result(
                "unavailable" if create.error else "failed",
                create,
                version,
                error=create.error or f"database creation exited {create.returncode}",
            )
        queries = _string_list(
            context.config.get(
                "queries",
                [
                    "codeql/python-queries@0.9.3:"
                    "codeql-suites/python-security-extended.qls"
                ],
            ),
            "queries",
        )
        analyze_argv = [
            *command,
            "database",
            "analyze",
            str(database),
            "--format=sarifv2.1.0",
            "--output",
            str(raw),
        ]
        query_timeout = context.config.get("query_timeout_seconds")
        if query_timeout is not None:
            analyze_argv.append(
                f"--timeout={_positive_number(query_timeout, 'query_timeout_seconds')}"
            )
        analyze_argv.extend(
            [
                *_string_list(context.config.get("analyze_args", []), "analyze_args"),
                *context.sample_args,
                *queries,
            ]
        )
        analyze = _run(context, analyze_argv, "analyze")
        commands = (create, analyze)
        if analyze.timed_out:
            return AdapterResult(
                status="timed_out",
                commands=commands,
                tool_version=version,
                error="analysis timed out",
            )
        if analyze.error or analyze.returncode != 0:
            return AdapterResult(
                status="unavailable" if analyze.error else "failed",
                commands=commands,
                tool_version=version,
                error=analyze.error or f"analysis exited {analyze.returncode}",
            )
        try:
            payload = json.loads(raw.read_text(encoding="utf-8"))
            finding_count = sum(
                len(run.get("results", []))
                for run in payload.get("runs", [])
                if isinstance(run, dict)
            )
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            return AdapterResult(
                status="failed",
                commands=commands,
                tool_version=version,
                error=f"invalid SARIF report: {exc}",
            )
        return AdapterResult(
            status="complete",
            commands=commands,
            tool_version=version,
            raw_output=raw.name,
            finding_count=finding_count,
            details={"queries": queries},
        )


class PysaAdapter(EngineAdapter):
    name = "pysa"

    def run(self, context: AdapterContext) -> AdapterResult:
        command = _command(context.config, default=("pyre",))
        version = probe_version([*command, "--version"], cwd=context.run_dir)
        results_dir = context.run_dir / "pysa-results"
        configuration: dict[str, Any] = {
            "site_package_search_strategy": context.config.get(
                "site_package_search_strategy", "pep561"
            ),
            "source_directories": [str(context.target)],
        }
        models = context.config.get("taint_models_path")
        if models:
            configuration["taint_models_path"] = str(models)
        configuration.update(
            _mapping(context.config.get("configuration", {}), "configuration")
        )
        (context.run_dir / ".pyre_configuration").write_text(
            json.dumps(configuration, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        argv = [
            *command,
            "analyze",
            "--save-results-to",
            str(results_dir),
        ]
        no_verify = context.config.get("no_verify", False)
        if not isinstance(no_verify, bool):
            raise ValueError("no_verify must be a boolean")
        if no_verify:
            argv.append("--no-verify")
        argv.extend(
            [
                *_string_list(context.config.get("args", []), "args"),
                *context.sample_args,
            ]
        )
        outcome = _run(context, argv, "analyze")
        if outcome.timed_out:
            return _result("timed_out", outcome, version, error="analysis timed out")
        if outcome.error or outcome.returncode != 0:
            return _result(
                "unavailable" if outcome.error else "failed",
                outcome,
                version,
                error=outcome.error or f"exit status {outcome.returncode}",
            )
        raw = results_dir / "taint-output.json"
        try:
            findings = 0
            for line in raw.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                value = json.loads(line)
                if isinstance(value, dict) and value.get("kind") == "issue":
                    findings += 1
        except (OSError, json.JSONDecodeError) as exc:
            return _result("failed", outcome, version, error=f"invalid report: {exc}")
        return AdapterResult(
            status="complete",
            commands=(outcome,),
            tool_version=version,
            raw_output=str(raw.relative_to(context.run_dir)),
            finding_count=findings,
        )


def adapter_for(name: str, config: Mapping[str, Any] | None = None) -> EngineAdapter:
    config = config or {}
    adapter_kind = config.get("adapter")
    if adapter_kind == "command":
        return CommandAdapter(name)
    if adapter_kind is not None and adapter_kind != "builtin":
        raise ValueError(f"unknown adapter type for {name!r}: {adapter_kind!r}")
    if name in PYFLOW_ENGINES:
        return PyFlowAdapter(name, PYFLOW_ENGINES[name])
    if name == "bandit":
        return BanditAdapter()
    if name == "codeql":
        return CodeQLAdapter()
    if name == "pysa":
        return PysaAdapter()
    raise ValueError(f"unknown benchmark engine: {name}")


def _report_path(context: AdapterContext, config: Mapping[str, Any]) -> Path | None:
    path = config.get("path")
    if path is None:
        return None
    if not isinstance(path, str) or not path:
        raise ValueError("report.path must be a non-empty string")
    report = (context.run_dir / path).resolve()
    if not report.is_relative_to(context.run_dir.resolve()):
        raise ValueError("report.path must stay within the run directory")
    return report


def _expand_argv(
    value: object,
    variables: Mapping[str, str],
    sample_args: Sequence[str],
    label: str,
) -> list[str]:
    argv = _string_list(value, label)
    expanded: list[str] = []
    for item in argv:
        if item == "{sample_args}":
            expanded.extend(sample_args)
        else:
            expanded.append(_expand(item, variables))
    if not expanded:
        raise ValueError(f"{label} must not be empty")
    return expanded


def _expand(value: str, variables: Mapping[str, str]) -> str:
    try:
        return value.format_map(variables)
    except KeyError as exc:
        raise ValueError(f"unknown command placeholder: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ValueError(f"invalid command template {value!r}: {exc}") from exc


def _returncodes(value: object, step_index: int) -> set[int]:
    if (
        not isinstance(value, list)
        or not value
        or not all(
            isinstance(item, int) and not isinstance(item, bool) for item in value
        )
    ):
        raise ValueError(
            f"steps[{step_index}].accepted_returncodes must be a non-empty integer list"
        )
    return set(value)


def _string_mapping(value: object, label: str) -> dict[str, str]:
    data = _mapping(value, label)
    if not all(isinstance(item, str) for item in data.values()):
        raise ValueError(f"{label} values must be strings")
    return {key: str(item) for key, item in data.items()}


def _read_declarative_report(
    path: Path | None, config: Mapping[str, Any]
) -> tuple[int | None, str | None]:
    if path is None:
        return None, None
    report_format = config.get("format", "json")
    if report_format == "json":
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    elif report_format == "jsonl":
        payload = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    elif report_format == "sarif":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return (
            sum(
                len(run.get("results", []))
                for run in payload.get("runs", [])
                if isinstance(run, dict) and isinstance(run.get("results", []), list)
            ),
            None,
        )
    elif report_format == "none":
        return None, None
    else:
        raise ValueError("report.format must be json, jsonl, sarif, or none")
    findings = _json_pointer(payload, config.get("findings_pointer", ""))
    status_pointer = config.get("analysis_status_pointer")
    status = _json_pointer(payload, status_pointer) if status_pointer else None
    if status is not None and not isinstance(status, str):
        raise ValueError("analysis status must be a string")
    if isinstance(findings, list):
        return len(findings), status
    if findings is None:
        return 0, status
    raise ValueError("findings pointer must resolve to a list")


def _json_pointer(value: Any, pointer: object) -> Any:
    if not isinstance(pointer, str):
        raise ValueError("JSON pointer must be a string")
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'")
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"invalid JSON pointer component: {part}") from exc
        else:
            return None
    return current


def _run(context: AdapterContext, argv: Sequence[str], stem: str) -> ProcessOutcome:
    return run_process(
        argv,
        cwd=context.run_dir,
        timeout_seconds=context.timeout_seconds,
        stdout_path=context.run_dir / f"{stem}.stdout.log",
        stderr_path=context.run_dir / f"{stem}.stderr.log",
    )


def _result(
    status: str,
    outcome: ProcessOutcome,
    version: str | None,
    *,
    error: str,
) -> AdapterResult:
    return AdapterResult(
        status=status,
        commands=(outcome,),
        tool_version=version,
        error=error,
    )


def _command(config: Mapping[str, Any], *, default: Sequence[str]) -> tuple[str, ...]:
    value = config.get("command", list(default))
    command = _string_list(value, "command")
    if not command:
        raise ValueError("command must not be empty")
    return tuple(command)


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{label} must be a list of strings")
    return list(value)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{label} must be a positive number")
    return float(value)
