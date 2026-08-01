from pyflow.analysis.entrypoints import (
    EntryPointDefaults,
    EntryPointMode,
    EntryPointOptions,
    ProcedureDescriptor,
    select_entry_points,
)


def _names(procedures, options):
    return tuple(item.identity for item in select_entry_points(procedures, options))


def test_declared_and_inferred_roots_share_one_selector():
    procedures = (
        ProcedureDescriptor("handler", "app.handler", callees=frozenset({"helper"})),
        ProcedureDescriptor("helper", "app.helper"),
        ProcedureDescriptor("task", "app.task", declared=True),
    )

    assert _names(
        procedures, EntryPointOptions(mode=EntryPointMode.DECLARED_PLUS_ROOTS)
    ) == ("handler", "task")


def test_file_public_normalizes_paths_and_can_exclude_module_bodies(tmp_path):
    source = tmp_path / "app.py"
    procedures = (
        ProcedureDescriptor(
            "module", "app.<module>", str(source), synthetic_module=True
        ),
        ProcedureDescriptor("handler", "app.handler", str(source)),
        ProcedureDescriptor("dependency", "dep.run", str(tmp_path / "dep.py")),
    )

    assert _names(
        procedures,
        EntryPointOptions(
            mode=EntryPointMode.FILE_PUBLIC,
            files=(str(source.parent / "." / source.name),),
            include_synthetic_modules=False,
        ),
    ) == ("handler",)


def test_parameter_taint_does_not_change_entry_selection():
    procedures = (ProcedureDescriptor("entry", "entry", declared=True),)
    clean = EntryPointOptions(mode=EntryPointMode.DECLARED_ONLY)
    tainted = EntryPointOptions(
        mode=EntryPointMode.DECLARED_ONLY, taint_parameters=True
    )

    assert _names(procedures, clean) == _names(procedures, tainted) == ("entry",)


def test_rule_pack_defaults_preserve_runtime_file_scope():
    resolved = EntryPointDefaults(taint_parameters=True).resolve(
        EntryPointOptions(
            mode=EntryPointMode.FILE_PUBLIC,
            files=("app.py",),
            taint_parameters=False,
        )
    )

    assert resolved.mode is EntryPointMode.FILE_PUBLIC
    assert resolved.files == ("app.py",)
    assert resolved.taint_parameters is True
