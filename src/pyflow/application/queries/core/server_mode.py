"""
Configuration helpers for MCP server modes.
"""

from enum import Enum
from typing import Dict, Optional


class MCPServerMode(Enum):
    """Selectable MCP server modes for agents."""

    BASIC = "basic"
    FULL = "full"
    ADVANCED = "advanced"


DEFAULT_MODE = MCPServerMode.FULL


def get_server_mode_description(mode: MCPServerMode) -> str:
    descriptions = {
        MCPServerMode.BASIC: "Lightweight mode exposing only CFG/callgraph facts.",
        MCPServerMode.FULL: "Full mode including callgraph, CFG/SSA, axioms and store graph.",
        MCPServerMode.ADVANCED: "Advanced mode adding alias, points-to, and lifetime facts.",
    }
    return descriptions.get(mode, "Custom MCP mode.")


def resolve_capabilities(mode: MCPServerMode) -> Dict[str, Dict[str, Optional[str]]]:
    """Return capability declarations for the requested MCP mode."""
    full = {
        "cfg": {"available": True, "note": None},
        "ssa": {"available": True, "note": None},
        "cdg": {"available": True, "note": None},
        "callgraph": {"available": True, "note": "Requires IPA analysis."},
        "callers": {"available": True, "note": "Requires IPA analysis."},
        "callees": {"available": True, "note": "Requires IPA analysis."},
        "function_summaries": {
            "available": True,
            "note": "Requires IPA analysis.",
        },
        "store_graph": {
            "available": True,
            "note": "Requires IPA/CPA analysis.",
        },
        "lifetime": {
            "available": True,
            "note": "Requires lifetime analysis.",
        },
        "reaching_defs": {
            "available": False,
            "note": "Derive from SSA form.",
        },
        "aliases": {
            "available": False,
            "note": "Use store graph + CPA dataflow.",
        },
        "points_to": {
            "available": False,
            "note": "Use store graph + CPA dataflow.",
        },
    }

    if mode is MCPServerMode.BASIC:
        basic = {
            key: value
            for key, value in full.items()
            if key in {"cfg", "callgraph", "callers", "callees", "function_summaries"}
        }
        basic["store_graph"] = {"available": False, "note": "Disabled in BASIC mode."}
        basic["lifetime"] = {"available": False, "note": "Disabled in BASIC mode."}
        basic["ssa"] = {
            "available": False,
            "note": "SSA is disabled to keep the footprint small.",
        }
        basic["cdg"] = {
            "available": False,
            "note": "CDG requires full SSA/CPA results.",
        }
        basic["reaching_defs"] = full["reaching_defs"]
        basic["aliases"] = full["aliases"]
        basic["points_to"] = full["points_to"]
        return basic

    if mode is MCPServerMode.ADVANCED:
        advanced = dict(full)
        advanced["aliases"] = {
            "available": True,
            "note": "Requires CPA/store graph wiring (not yet implemented).",
        }
        advanced["points_to"] = {
            "available": True,
            "note": "Requires CPA/store graph wiring (not yet implemented).",
        }
        advanced["reaching_defs"] = {
            "available": True,
            "note": "Derived from SSA in ADVANCED mode.",
        }
        return advanced

    return full
