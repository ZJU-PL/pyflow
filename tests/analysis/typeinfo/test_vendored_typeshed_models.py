"""Stdlib modeling backed by the vendored typeshed snapshot."""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.typeinfo import (
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
    TypeInfoService,
)
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.modules.type_stubs import default_typeshed_roots, parse_stub_source


def _infer(source: str):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_vendored_typeshed_is_shipped() -> None:
    roots = default_typeshed_roots()

    assert roots
    root = roots[0]
    assert (root / "stdlib" / "hashlib.pyi").is_file()
    assert (root / "stdlib" / "urllib" / "parse.pyi").is_file()
    assert (root / "LICENSE").is_file()


def test_typeshed_models_hashlib_and_base64_returns() -> None:
    result = _infer(
        "import base64\n"
        "import hashlib\n"
        "digest = hashlib.sha256(b'a').digest()\n"
        "hexdigest = hashlib.sha256(b'a').hexdigest()\n"
        "encoded = base64.b64encode(b'a')\n"
        "decoded = base64.b64decode('YQ==')\n"
    )

    assert str(result.type_of("digest")) == "bytes"
    assert str(result.type_of("hexdigest")) == "str"
    assert str(result.type_of("encoded")) == "bytes"
    assert str(result.type_of("decoded")) == "bytes"
    assert result.diagnostics == []


def test_typeshed_models_struct_and_os_read() -> None:
    result = _infer(
        "import os\n"
        "import struct\n"
        "packed = struct.pack('<i', 1)\n"
        "fd = os.open('x', os.O_RDONLY)\n"
        "chunk = os.read(fd, 10)\n"
    )

    assert str(result.type_of("packed")) == "bytes"
    assert str(result.type_of("fd")) == "int"
    assert str(result.type_of("chunk")) == "bytes"


def test_typeshed_models_urllib_urlparse_attributes() -> None:
    result = _infer(
        "from urllib.parse import urlparse\n"
        "parsed = urlparse('http://example.com/path?q=1')\n"
        "netloc = parsed.netloc\n"
        "path = parsed.path\n"
    )

    assert "ParseResult" in str(result.type_of("parsed"))
    # ``ParseResult`` specializes ``_ResultComponentT`` to ``str``; the old
    # behaviour reported the type variable's full constraint set.
    assert str(result.type_of("netloc")) == "str"
    assert str(result.type_of("path")) == "str"


def test_typeshed_models_sqlite_and_random_aliases() -> None:
    result = _infer(
        "import random\n"
        "import sqlite3\n"
        "conn = sqlite3.connect(':memory:')\n"
        "cursor = conn.cursor()\n"
        "rows = cursor.execute('select 1').fetchall()\n"
        "value = random.random()\n"
        "count = random.randint(0, 10)\n"
    )

    assert "Connection" in str(result.type_of("conn"))
    assert "Cursor" in str(result.type_of("cursor"))
    assert "list" in str(result.type_of("rows"))
    assert str(result.type_of("value")) == "float"
    assert str(result.type_of("count")) == "int"


def test_typeshed_iterator_members_support_csv_rows() -> None:
    result = _infer(
        "import csv\n"
        "with open('x') as handle:\n"
        "    reader = csv.reader(handle)\n"
        "    for row in reader:\n"
        "        cell = row[0]\n"
    )

    assert str(result.type_of("row")) == "list[str]"
    assert str(result.type_of("cell")) == "str"


def test_typeshed_stub_modules_are_not_inferred_as_implementation_source() -> None:
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("hashlib")

    assert service.inference_result("hashlib") is None
    assert not [
        diagnostic
        for diagnostic in service.diagnostics()
        if diagnostic.code in {"type_source_failed", "type_stub_failed"}
    ]


def test_project_engine_uses_typeshed_for_stdlib(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import hashlib\n" "hexdigest = hashlib.sha256(b'a').hexdigest()\n",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg"])

    assert str(result.type_of("pkg.hexdigest")) == "str"


def test_stub_parser_selects_the_active_python_version() -> None:
    info = parse_stub_source(
        "import sys\n"
        "if sys.version_info >= (3, 99):\n"
        "    def f() -> int: ...\n"
        "else:\n"
        "    def f() -> str: ...\n",
        python_version=(3, 13),
    )

    assert [function.returns for function in info.functions] == ["str"]


def test_project_local_module_named_like_a_core_stub_is_analyzed(tmp_path: Path) -> None:
    (tmp_path / "typing.py").write_text("value: int = 1\n", encoding="utf-8")

    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("typing")

    assert str(service.type_of("typing", "value")) == "int"
