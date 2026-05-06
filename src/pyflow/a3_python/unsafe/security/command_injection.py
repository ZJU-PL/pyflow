"""
COMMAND_INJECTION (CWE-078): Tainted data in shell commands.

Unsafe region U_cmdi := { s | π == π_shell ∧ τ(cmd) == 1 ∧ ShellEnabled ∧ ¬Escaped }

Sources: User input, environment variables, HTTP parameters
Sinks: os.system, subprocess.call(shell=True), os.popen
Sanitizers: shlex.quote, using array form without shell=True
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_command_injection(state) -> bool:
    """
    Unsafe predicate U_COMMAND_INJECTION(σ).
    
    Returns True if:
    - At shell command execution sink
    - Command argument has untrusted taint τ=1
    - shell=True or using os.system/os.popen
    - Command not escaped with shlex.quote
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.COMMAND_SHELL:
                return True
    
    if hasattr(state, 'command_injection_detected') and state.command_injection_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for command injection."""
    result = {
        "bug_type": "COMMAND_INJECTION",
        "cwe": "CWE-078",
        "severity": "critical",
        "location": "unknown",
        "taint_sources": [],
        "command_snippet": None,
        "shell_enabled": True,
        "message": "Potential command injection: untrusted data in shell command",
        "barrier_info": {
            "unsafe_region": "U_cmdi := { s | at_shell_sink ∧ τ(cmd)=1 ∧ shell_enabled ∧ ¬escaped }",
            "barrier_template": "B = δ_shell · (escaped + ¬shell + (1-τ) - ½)",
            "required_guard": "shlex.quote() or shell=False with array args"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.COMMAND_SHELL:
                result["location"] = v.sink_location
                result["taint_sources"] = [
                    {"source": l.source_type.name, "location": l.source_location}
                    for l in v.taint_sources
                ]
                result["message"] = v.message
                break
    
    if path_trace:
        result["path_trace_suffix"] = path_trace[-10:]
    
    return result
