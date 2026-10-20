"""Real-world stdlib bindings must survive import and decorator lowering."""

from pyflow.analysis.alias.kcfa import PointerAnalysis


def test_builtin_method_decorators_and_property_getters_resolve():
    result = PointerAnalysis("""
class Box:
    @staticmethod
    def create_value(): return object()
    @classmethod
    def make(cls): return cls()
    @property
    def value(self): return self.item
box = Box.make()
box.item = object()
read_value = box.value
static_result = Box.create_value()
""").run()
    assert result.points_to("read_value")
    assert result.points_to("static_result")
    assert any("value" in callee for _, callee in result.call_edges())
    assert not any(
        name in detail["message"]
        for detail in result.unknown_details()
        for name in ("[global]property", "[global]classmethod", "[global]staticmethod")
    )


def test_os_path_import_spellings_and_datetime_classmethods_resolve():
    for import_line, call in [
        ("import os.path", "os.path.join"),
        ("import os", "os.path.join"),
        ("from os.path import join", "join"),
    ]:
        result = PointerAnalysis(import_line + f"\npath_result={call}('a', 'b')\n").run()
        assert result.points_to("path_result")
        assert not result.unknown_details()
    result = PointerAnalysis("from datetime import datetime\ndate_result=datetime.now()\n").run()
    assert result.points_to("date_result")
    assert any("datetime.now" in callee for _, callee in result.call_edges())


def test_dotted_import_binds_parent_and_reuses_module_identity(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "sub.py").write_text("def make(): return object()\n")
    entry = tmp_path / "entry.py"
    entry.write_text(
        "import pkg.sub\nimport pkg.sub as direct\nresult=pkg.sub.make()\nother=direct.make()\n"
    )
    result = PointerAnalysis.from_project(entry, project_path=tmp_path).run()
    assert result.points_to("result")
    assert result.points_to("other")
    assert not any("empty points-to set" in item["message"] for item in result.unknown_details())


def test_object_sensitive_policies_analyze_allocations_and_method_calls():
    source = "class Box:\n    def value(self): return self\na=Box()\nb=a.value()\n"
    for depth in (1, 2, 3):
        result = PointerAnalysis(source, context_policy=f"{depth}-obj").run()
        assert result.points_to("a")
        assert result.points_to("b")
        assert result.points_to("a") == result.points_to("b")
        assert any("fn value(" in callee for _, callee in result.call_edges())
