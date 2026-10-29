"""Follow-up typing regressions from real-project evaluation."""

import contextvars
import datetime
import itertools
import pathlib
import re
import types
import uuid

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.core.typesystem import CallableType, Instance, NoneType, UnionType
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup, resolve_annotation


def raw_types(typ):
    if isinstance(typ, NoneType):
        return {type(None)}
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, UnionType):
        return set().union(*(raw_types(item) for item in typ.items))
    return set()


def infer(source, **options):
    return StaticTypeInferenceEngine(options=InferenceOptions(**options)).infer_source(
        "sample", source
    )


def test_static_methods_do_not_receive_instance_or_class_receiver():
    result = infer("""
class ProxyConfig:
    @staticmethod
    def from_string(proxy_str: str) -> "ProxyConfig":
        return ProxyConfig()
    @classmethod
    def from_dict(cls, values: dict) -> "ProxyConfig":
        return cls()
    def build(self) -> "ProxyConfig":
        return self.__class__.from_string("local")
class Helper:
    @staticmethod
    def _indent(text: str) -> str:
        return text
    def run(self) -> str:
        return self._indent("hello")
config = ProxyConfig.from_string("http://localhost")
other = ProxyConfig().from_string("local")
by_dict = ProxyConfig.from_dict({})
text = Helper().run()
""")
    assert not result.diagnostics
    for name in ("config", "other", "by_dict"):
        assert result.type_of(name).type.full_name == "sample.ProxyConfig"
    assert raw_types(result.type_of("text")) == {str}


def test_static_method_wrong_argument_is_still_reported():
    result = infer(
        """
class Config:
    @staticmethod
    def parse(value: int) -> str:
        return str(value)
value = Config.parse("not an int")
""",
        strict_annotations=True,
    )
    assert [(d.code, d.severity) for d in result.diagnostics] == [("annotation-mismatch", "error")]
    assert "argument value" in result.diagnostics[0].message


def test_recursive_collection_return_is_bounded_and_converges():
    result = infer(
        """
class ImageProcessor:
    def fetch_images(self, urls):
        if isinstance(urls, (list, tuple)):
            return [self.fetch_images(item) for item in urls]
        return "image-bytes"
""",
        max_iterations=24,
    )
    assert result.converged
    assert result.iterations < 24
    assert not [d for d in result.diagnostics if d.code == "inference-did-not-converge"]


def test_fresh_container_literals_may_widen_but_existing_aliases_remain_invariant():
    result = infer("""
prefixes: list[str | None] = [None] * 3
single: list[str | None] = [None]
comprehended: list[str | None] = [None for _ in range(3)]
existing = [None]
aliased: list[str | None] = existing
bad: list[str | None] = [1]
""")
    mismatches = [d for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert len(mismatches) == 2
    assert mismatches[0].span.lineno == 6
    assert mismatches[1].span.lineno == 7
    assert raw_types(result.type_of("prefixes").args[0]) == {str, type(None)}


def test_typed_dict_shape_flows_through_helpers_and_call_arguments():
    result = infer("""
from typing import TypedDict
class Config(TypedDict):
    host: str
    port: int
def load_config():
    config = {"host": "localhost", "port": 8080}
    return config
def get_config() -> Config:
    return load_config()
def run(config: Config) -> str:
    return config["host"]
result = run(get_config())
direct = run({"host": "direct", "port": 9000})
""")
    assert not result.diagnostics
    assert raw_types(result.type_of("result")) == {str}
    assert raw_types(result.type_of("direct")) == {str}


def test_typed_dict_shape_still_validates_nested_helper_result():
    result = infer(
        """
from typing import TypedDict
class Config(TypedDict):
    host: str
    port: int
def load_config():
    return {"host": "localhost"}
def get_config() -> Config:
    return load_config()
""",
        strict_annotations=True,
    )
    assert any(
        d.code == "annotation-mismatch" and "missing keys ['port']" in d.message
        for d in result.diagnostics
    )


def test_pep484_and_613_module_type_aliases():
    result = infer("""
from typing import Literal, Union, TypeAlias
from typing_extensions import TypeAlias as Alias
JustifyMethod = Literal["default", "left", "center", "right", "full"]
StyleType = Union[str, "Style"]
Nested = list[dict[str, int]]
Modern: TypeAlias = str | int
Extended: Alias = bytes | None
class Style: pass
def render(justify: JustifyMethod, style: StyleType, nested: Nested,
           modern: Modern, extended: Extended) -> str:
    return "rendered"
""")
    parameters = result.functions["sample.render"].parameters
    assert raw_types(parameters["justify"].public_type()) == {str}
    assert raw_types(parameters["style"].public_type()) == {
        str,
        result.type_of("Style").type.raw_type,
    }
    assert raw_types(parameters["modern"].public_type()) == {str, int}
    assert raw_types(parameters["extended"].public_type()) == {bytes, type(None)}
    nested = parameters["nested"].public_type()
    assert isinstance(nested, Instance)
    assert nested.type.raw_type is list
    assert not result.diagnostics


def test_standard_library_annotations_resolve_without_importing_target_code():
    lookup = BuiltinTypeLookup()
    cases = {
        "itertools.chain[int]": itertools.chain,
        "pathlib.Path": pathlib.Path,
        "Path": pathlib.Path,
        "datetime.date": datetime.date,
        "datetime": datetime.datetime,
        "re.Pattern[str]": re.Pattern,
        "Pattern[str]": re.Pattern,
        "uuid.UUID": uuid.UUID,
        "types.TracebackType": types.TracebackType,
        "contextvars.ContextVar[str]": contextvars.ContextVar,
    }
    for annotation, expected in cases.items():
        typ = resolve_annotation(annotation, lookup)
        assert isinstance(typ, Instance)
        assert typ.type.raw_type is expected

    result = infer("""
import itertools
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Optional
def process(chain: itertools.chain[int], path: Path,
            now: Optional[Callable[[], datetime]]) -> date:
    return date.today()
""")
    assert not result.diagnostics
    assert raw_types(result.functions["sample.process"].return_type) == {datetime.date}
    callable_type = resolve_annotation(
        "Callable[[], datetime]",
        lookup,
        aliases={"Callable": "typing.Callable", "datetime": "datetime.datetime"},
    )
    assert isinstance(callable_type, CallableType)
    assert callable_type.return_type.type.raw_type is datetime.datetime
