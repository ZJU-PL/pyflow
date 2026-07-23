#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from pyflow.analysis.typeinfo.resolution.stubs import (
    StubResolver,
    build_stub_map,
    clear_stub_map_cache,
    find_adjacent_pyi,
    find_package_pyi,
    find_stub_packages,
    get_cached_stub_map,
    parse_stub_file,
)
from pyflow.frontend.project_resolution import ProjectContext
from pyflow.analysis import typeinfo


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_dir() -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("__init__.pyi").write_text("")
        root.joinpath("os.pyi").write_text("")
        root.joinpath("sys.pyi").write_text("")
        pkg = root / "json"
        pkg.mkdir()
        pkg.joinpath("__init__.pyi").write_text("")
        pkg.joinpath("encoder.pyi").write_text("")
        yield root


@pytest.fixture
def typeshed_dir() -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        stdlib = root / "stdlib" / "3.10"
        stdlib.mkdir(parents=True)
        stdlib.joinpath("builtins.pyi").write_text("")
        stdlib.joinpath("os").mkdir()
        stdlib.joinpath("os", "__init__.pyi").write_text("")
        stdlib.joinpath("typing.pyi").write_text("")
        stubs = root / "stubs" / "requests"
        stubs.mkdir(parents=True)
        stubs.joinpath("__init__.pyi").write_text("")
        yield root


# ---------------------------------------------------------------------------
# build_stub_map
# ---------------------------------------------------------------------------


def test_build_stub_map_flat_directory(stub_dir: Path) -> None:
    result = build_stub_map([stub_dir])
    assert result.get("os") is not None
    assert result.get("sys") is not None
    assert result.get("json") is not None
    assert result.get("json.encoder") is not None
    # __init__.pyi -> package name = directory name
    json_path = result["json"]
    assert json_path.endswith("__init__.pyi")


def test_build_stub_map_nested_modules_use_dotted_names() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pkg = root / "pkg"
        pkg.mkdir()
        pkg.joinpath("__init__.pyi").write_text("")
        pkg.joinpath("mod.pyi").write_text("")

        result = build_stub_map([root])

        assert "pkg" in result
        assert "pkg.mod" in result
        assert "mod" not in result


def test_build_stub_map_typeshed(typeshed_dir: Path) -> None:
    result = build_stub_map([typeshed_dir], python_version=(3, 10))
    assert result.get("builtins") is not None
    assert result.get("os") is not None
    assert result.get("typing") is not None
    assert result.get("requests") is not None


def test_build_stub_map_empty_directory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = build_stub_map([Path(tmp)])
    assert result == {}


def test_build_stub_map_nonexistent_directory() -> None:
    result = build_stub_map([Path("/nonexistent/path")])
    assert result == {}


def test_build_stub_map_ignores_non_pyi() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("foo.py").write_text("")
        root.joinpath("bar.txt").write_text("")
        result = build_stub_map([root])
    assert result == {}


# ---------------------------------------------------------------------------
# find_adjacent_pyi
# ---------------------------------------------------------------------------


def test_find_adjacent_pyi_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        py_path = Path(tmp) / "module.py"
        pyi_path = Path(tmp) / "module.pyi"
        py_path.write_text("")
        pyi_path.write_text("")
        result = find_adjacent_pyi(py_path)
        assert result == str(pyi_path)


def test_find_adjacent_pyi_not_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        py_path = Path(tmp) / "module.py"
        py_path.write_text("")
        result = find_adjacent_pyi(py_path)
        assert result is None


# ---------------------------------------------------------------------------
# find_package_pyi
# ---------------------------------------------------------------------------


def test_find_package_pyi_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "mypackage"
        pkg.mkdir()
        pkg.joinpath("__init__.pyi").write_text("")
        result = find_package_pyi(pkg)
        assert result is not None
        assert result.endswith("__init__.pyi")


def test_find_package_pyi_not_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "mypackage"
        pkg.mkdir()
        result = find_package_pyi(pkg)
        assert result is None


# ---------------------------------------------------------------------------
# find_stub_packages
# ---------------------------------------------------------------------------


def test_find_stub_packages_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        sys_path_entry = Path(tmp)
        stub_pkg = sys_path_entry / "foo-stubs"
        stub_pkg.mkdir()
        stub_pkg.joinpath("__init__.pyi").write_text("")
        result = find_stub_packages([str(sys_path_entry)], "foo")
        assert len(result) == 1
        assert "foo-stubs" in result[0]


def test_find_stub_packages_not_found() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = find_stub_packages([tmp], "nonexistent")
        assert result == []


# ---------------------------------------------------------------------------
# get_cached_stub_map
# ---------------------------------------------------------------------------


def test_get_cached_stub_map_caches(stub_dir: Path) -> None:
    clear_stub_map_cache()
    result1 = get_cached_stub_map([stub_dir])
    result2 = get_cached_stub_map([stub_dir])
    assert result1 is result2  # same object (cached)


def test_get_cached_stub_map_different_key() -> None:
    clear_stub_map_cache()
    with tempfile.TemporaryDirectory() as tmp:
        d1 = Path(tmp)
        d1.joinpath("a.pyi").write_text("")
        d2 = Path(tmp) / "sub"
        d2.mkdir()
        result1 = get_cached_stub_map([d1])
        result2 = get_cached_stub_map([d2])
        assert result1 is not result2


# ---------------------------------------------------------------------------
# parse_stub_file
# ---------------------------------------------------------------------------


def test_parse_stub_function() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text("def greet(name: str) -> str: ...\n")
        info = parse_stub_file(pyi)
        assert len(info.functions) == 1
        f = info.functions[0]
        assert f.name == "greet"
        assert f.params == [("name", "str")]
        assert f.returns == "str"


def test_parse_stub_function_multiple_params() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text("def add(a: int, b: int) -> int: ...\n")
        info = parse_stub_file(pyi)
        assert len(info.functions) == 1
        f = info.functions[0]
        assert len(f.params) == 2
        assert f.params[0] == ("a", "int")
        assert f.params[1] == ("b", "int")


def test_parse_stub_function_no_return() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text("def hello(name: str): ...\n")
        info = parse_stub_file(pyi)
        assert info.functions[0].returns is None


def test_parse_stub_function_with_star_args() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text("def log(msg: str, *args: str) -> None: ...\n")
        info = parse_stub_file(pyi)
        f = info.functions[0]
        param_names = [p[0] for p in f.params]
        assert "*args" in param_names


def test_parse_stub_function_with_keyword_only_args() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text("def configure(*, retries: int, name: str) -> None: ...\n")
        info = parse_stub_file(pyi)

        assert info.functions[0].params == [("retries", "int"), ("name", "str")]
        assert info.functions[0].param_kinds["retries"] == "kwonly"
        assert info.functions[0].param_kinds["name"] == "kwonly"


def test_stub_resolver_prefers_adjacent_pyi() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("mod.py").write_text("def f():\n    return object()\n")
        root.joinpath("mod.pyi").write_text("def f() -> int: ...\n")
        resolver = StubResolver(ProjectContext(root))

        resolved = resolver.resolve("mod")

        assert resolved is not None
        assert resolved.source == "adjacent"
        assert resolved.info.functions[0].returns == "int"


def test_stub_resolver_resolves_nested_pep561_stub_package() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pkg = root / "foo-stubs" / "bar"
        pkg.mkdir(parents=True)
        pkg.joinpath("__init__.pyi").write_text("def g() -> str: ...\n")
        resolver = StubResolver(ProjectContext(root))

        resolved = resolver.resolve("foo.bar")

        assert resolved is not None
        assert resolved.source == "stub-package"
        assert resolved.info.functions[0].name == "g"


def test_stub_resolver_parses_in_memory_pyi_source_map() -> None:
    resolver = StubResolver(
        ProjectContext(
            None,
            source_files={"mem/pkg/mod.pyi": "def f() -> bool: ...\n"},
        )
    )

    resolved = resolver.resolve("mem.pkg.mod")

    assert resolved is not None
    assert resolved.source == "source-map"
    assert resolved.info.functions[0].returns == "bool"


def test_stub_resolver_resolves_typeshed_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "stubs" / "vendor"
        package.mkdir(parents=True)
        package.joinpath("__init__.pyi").write_text("def f() -> int: ...\n")
        resolver = StubResolver(ProjectContext(None), typeshed_roots=[root])

        resolved = resolver.resolve("vendor")

        assert resolved is not None
        assert resolved.source == "typeshed"
        assert resolved.info.functions[0].name == "f"


def test_typeinfo_package_exports_stub_resolver_api() -> None:
    assert typeinfo.StubResolver is StubResolver
    assert callable(typeinfo.parse_stub_source)


def test_stub_resolver_reports_parse_diagnostics() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("bad.py").write_text("")
        root.joinpath("bad.pyi").write_text("def broken(: ...\n")
        resolver = StubResolver(ProjectContext(root))

        assert resolver.resolve("bad") is None
        diagnostics = resolver.get_diagnostics()
        assert diagnostics
        assert diagnostics[0].code == "stub_parse_failed"


def test_parse_stub_class() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text(
            "class MyClass(BaseClass):\n"
            "    def method(self, x: int) -> str: ...\n"
            "    attr: int\n"
        )
        info = parse_stub_file(pyi)
        assert len(info.classes) == 1
        cls = info.classes[0]
        assert cls.name == "MyClass"
        assert "BaseClass" in cls.bases
        assert len(cls.methods) == 1
        assert cls.methods[0].name == "method"
        assert len(cls.class_vars) == 1
        assert cls.class_vars[0] == ("attr", "int")


def test_parse_stub_variables() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text(
            "x: int\n"
            "y: str\n"
            "z: List[int]\n"
        )
        info = parse_stub_file(pyi)
        assert len(info.variables) == 3
        names = {v[0] for v in info.variables}
        assert names == {"x", "y", "z"}


def test_parse_stub_generic_function() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text(
            "from typing import Optional\n"
            "def find(key: str) -> Optional[int]: ...\n"
        )
        info = parse_stub_file(pyi)
        assert info.functions[0].returns == "Optional[int]"


def test_parse_stub_with_decorators() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pyi = Path(tmp) / "mod.pyi"
        pyi.write_text(
            "@overload\n"
            "def foo(x: int) -> str: ...\n"
            "@overload\n"
            "def foo(x: str) -> int: ...\n"
        )
        info = parse_stub_file(pyi)
        assert len(info.functions) == 2
        assert "overload" in info.functions[0].decorators
