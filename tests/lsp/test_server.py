"""Tests for pyflow.lsp.server — PyflowAnalysisServer query methods."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pyflow.api.queries import MCPServerMode
from pyflow.lsp.server import PyflowAnalysisServer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_service():
    """A SemanticQueryService with all query methods mocked."""
    svc = MagicMock()
    svc.capabilities.return_value = {"callgraph": True}
    svc.get_callgraph_data.return_value = {"nodes": ["a", "b"], "edges": []}
    svc.get_callers.return_value = ["caller1", "caller2"]
    svc.get_callees.return_value = ["callee1"]
    svc.get_downstream_functions.return_value = ["d1", "d2"]
    svc.get_upstream_functions.return_value = ["u1"]
    svc.get_shortest_path.return_value = ["a", "b", "c"]
    svc.get_cfg_structure.return_value = {"nodes": []}
    svc.get_reaching_defs.return_value = {"x": []}
    svc.get_ipa_function_summaries.return_value = []
    svc.get_expression_type.return_value = "int"
    svc.get_aliases_for_variable.return_value = MagicMock(
        variable="x",
        aliases=set(),
        is_aliased=False,
        ref_count=1,
        is_escaped=False,
    )
    svc.get_points_to_for_variable.return_value = MagicMock(
        variable="x",
        points_to=set(),
        may_be_null=False,
        ref_count=1,
        is_escaped=False,
    )
    profile_mock = MagicMock()
    profile_mock.configure_mock(
        name="f",
        signature="()",
        parameters=[],
        return_type="int",
        calls=[],
        called_by=[],
        has_branches=False,
        has_loops=False,
        complexity=1,
        external_dependencies=[],
    )
    svc.get_function_test_profile.return_value = profile_mock
    return svc


@pytest.fixture
def server(mock_service):
    srv = PyflowAnalysisServer(server_mode=MCPServerMode.ADVANCED)
    srv._loaded = True
    srv._service = mock_service
    srv._compiler = MagicMock()
    srv._program = MagicMock()
    srv._program.liveCode = []
    return srv


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_is_loaded_property(self, server):
        assert server.is_loaded is True

    def test_is_loaded_returns_false_when_not_loaded(self):
        srv = PyflowAnalysisServer()
        assert srv.is_loaded is False

    def test_service_property_returns_service(self, server):
        assert server.service is not None

    def test_service_property_raises_when_not_loaded(self):
        srv = PyflowAnalysisServer()
        with pytest.raises(RuntimeError, match="not loaded"):
            _ = srv.service

    def test_compiler_property_returns_compiler(self, server):
        assert server.compiler is not None

    def test_program_property_returns_program(self, server):
        assert server.program is not None

    def test_close_resets_state(self, server):
        server.close()
        assert server.is_loaded is False
        with pytest.raises(RuntimeError):
            _ = server.service


# ---------------------------------------------------------------------------
# Query methods
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_get_capabilities(self, server):
        caps = server.get_capabilities()
        assert caps == {"callgraph": True}
        server.service.capabilities.assert_called_once()

    def test_full_mode_rejects_advanced_alias_query(self, mock_service):
        server = PyflowAnalysisServer(server_mode=MCPServerMode.FULL)
        server._loaded = True
        server._service = mock_service
        with pytest.raises(RuntimeError, match="ADVANCED|unavailable"):
            server.get_aliases_for_variable("x")


class TestCallGraph:
    def test_get_callgraph_data(self, server):
        data = server.get_callgraph_data()
        assert data == {"nodes": ["a", "b"], "edges": []}

    def test_get_callers(self, server):
        result = server.get_callers("foo")
        assert result == ["caller1", "caller2"]
        server.service.get_callers.assert_called_with("foo")

    def test_get_callees(self, server):
        result = server.get_callees("foo")
        assert result == ["callee1"]
        server.service.get_callees.assert_called_with("foo")

    def test_get_downstream_functions(self, server):
        result = server.get_downstream_functions("foo", max_depth=3)
        assert result == ["d1", "d2"]

    def test_get_upstream_functions(self, server):
        result = server.get_upstream_functions("foo")
        assert result == ["u1"]

    def test_get_shortest_path(self, server):
        result = server.get_shortest_path("a", "z")
        assert result == ["a", "b", "c"]


class TestControlFlow:
    def test_get_cfg_structure(self, server):
        result = server.get_cfg_structure("foo")
        assert result == {"nodes": []}


class TestDataFlow:
    def test_get_reaching_defs(self, server):
        with pytest.raises(RuntimeError, match="unavailable"):
            server.get_reaching_defs("foo")

    def test_get_ipa_function_summaries(self, server):
        result = server.get_ipa_function_summaries()
        assert result == []


class TestTypeInfo:
    def test_get_expression_type(self, server):
        result = server.get_expression_type("mod", 1, 0)
        assert result == {"type": "int"}

    def test_get_expression_type_returns_none_when_service_returns_none(self, server):
        server.service.get_expression_type.return_value = None
        result = server.get_expression_type("mod", 1, 0)
        assert result is None


class TestAlias:
    def test_get_aliases_for_variable(self, server):
        result = server.get_aliases_for_variable("x")
        assert result["variable"] == "x"
        assert result["is_aliased"] is False

    def test_get_points_to_for_variable(self, server):
        result = server.get_points_to_for_variable("x")
        assert result["variable"] == "x"


class TestTestGeneration:
    def test_get_function_test_profile(self, server):
        result = server.get_function_test_profile("f")
        assert result["name"] == "f"
        assert result["complexity"] == 1
