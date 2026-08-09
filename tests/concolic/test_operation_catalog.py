from pyflow.concolic import OperationSupport, discover_operations


def test_operation_catalog_resolves_imports_and_ranks_calls(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "import math as m\n"
        "from mystery import transform as change\n"
        "def local(value):\n"
        "    return value\n"
        "def target(value):\n"
        "    return local(m.floor(value)) + change(value) + len([value])\n",
        encoding="utf-8",
    )

    catalog = discover_operations(tmp_path)
    support = {operation.name: operation.support for operation in catalog.operations}

    assert support["math.floor"] is OperationSupport.MODELLED
    assert support["mystery.transform"] is OperationSupport.UNKNOWN
    assert support["local"] is OperationSupport.LOCAL
    assert support["len"] is OperationSupport.BUILTIN
    assert catalog.unknown[0].name == "mystery.transform"


def test_operation_catalog_accepts_stub_corpora(tmp_path):
    stub = tmp_path / "api.pyi"
    stub.write_text(
        "import decimal\n"
        "def normalize(value: str) -> str:\n"
        "    return decimal.Decimal(value).normalize()\n",
        encoding="utf-8",
    )

    catalog = discover_operations(stub)

    assert any(operation.name == "decimal.Decimal" for operation in catalog.operations)
