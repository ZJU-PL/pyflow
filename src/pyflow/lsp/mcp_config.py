"""MCP-adapter policy mapped onto protocol-neutral analysis configuration."""

from __future__ import annotations

from enum import Enum

from pyflow.application.analysis_snapshot import AnalysisConfig


class MCPServerMode(Enum):
    """CLI convenience presets for MCP/LSP server startup only."""

    BASIC = "basic"
    FULL = "full"
    ADVANCED = "advanced"


DEFAULT_MODE = MCPServerMode.FULL


def analysis_config_for_mode(mode: MCPServerMode) -> AnalysisConfig:
    """Translate an adapter preset into core analysis selections."""

    if mode is MCPServerMode.BASIC:
        return AnalysisConfig(ipa=True, cpa=False, lifetime=False, heap=False)
    if mode is MCPServerMode.ADVANCED:
        return AnalysisConfig(ipa=True, cpa=True, lifetime=True, heap=True)
    return AnalysisConfig()
