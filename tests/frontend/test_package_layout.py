"""Canonical package-layout checks for the reorganized frontend."""

from importlib.util import find_spec

import pyflow.frontend as frontend
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.extractor import Extractor
from pyflow.frontend.resolution.dependencies import DependencyResolver
from pyflow.language.modules.project_resolution import ProjectContext


def test_implementations_live_in_canonical_modules():
    assert ASTConverter.__module__ == "pyflow.frontend.conversion.ast"
    assert DependencyResolver.__module__ == "pyflow.frontend.resolution.dependencies"
    assert Extractor.__module__ == "pyflow.frontend.extractor"
    assert ProjectContext.__module__ == "pyflow.language.modules.project_resolution"


def test_frontend_root_has_no_compatibility_exports():
    assert not hasattr(frontend, "ASTConverter")
    assert not hasattr(frontend, "DependencyResolver")
    assert not hasattr(frontend, "Extractor")
    assert not hasattr(frontend, "ProjectContext")


def test_flat_compatibility_modules_are_not_present():
    removed_modules = (
        "pyflow.frontend.ast_converter",
        "pyflow.frontend.class_hierarchy",
        "pyflow.frontend.dependency_resolver",
        "pyflow.frontend.function_extractor",
        "pyflow.frontend.object_manager",
        "pyflow.frontend.programextractor",
        "pyflow.frontend.project_resolution",
        "pyflow.frontend.source_locator",
        "pyflow.frontend.stub_manager",
        "pyflow.frontend.resolution.imports",
        "pyflow.frontend.resolution.project",
        "pyflow.analysis.ir_utils",
        "pyflow.analysis.typeinfo.resolution.stubs",
    )
    assert all(find_spec(module_name) is None for module_name in removed_modules)
