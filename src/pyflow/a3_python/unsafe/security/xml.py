"""
XML-related security bug detectors (barrier-certificate-theory.md §11).

Bug Types:
- XML_BOMB (CWE-776): XML internal entity expansion (billion laughs)
- TAR_SLIP (CWE-022): Arbitrary file write during tarfile extraction

Note: XML_BOMB detection now uses the lattice-based detector in
a3_python.unsafe.security.lattice_detectors for precise taint tracking.
"""

from typing import Any, Optional
from a3_python.unsafe.security.lattice_detectors import (
    XML_BOMB_DETECTOR,
)


# ============================================================================
# XML_BOMB (CWE-776): py/xml-bomb
# ============================================================================

def is_unsafe_xml_bomb(state) -> bool:
    """
    Check if state is in unsafe region for XML bomb (billion laughs).
    
    Unsafe region:
    U_xmlbomb := { s | π == π_xml_parse ∧ τ(xml_input) == 1 ∧ EntityExpansionUnlimited(parser) }
    
    Detection requires:
    - At XML parsing site
    - XML input is tainted (from untrusted source)
    - Entity expansion is not limited
    
    Now delegates to lattice-based detector for precise taint tracking.
    """
    return XML_BOMB_DETECTOR.is_unsafe(state)


def extract_xml_bomb_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for XML bomb vulnerability."""
    return {
        "bug_type": "XML_BOMB",
        "cwe": "CWE-776",
        "query_id": "py/xml-bomb",
        "description": "XML internal entity expansion (billion laughs attack)",
        "trace": trace,
        "parser_site": getattr(state, 'xml_bomb_site', None),
        "tainted_input": getattr(state, 'xml_bomb_input', None),
        "mitigation": "Use defusedxml or disable entity expansion"
    }


# ============================================================================
# TAR_SLIP (CWE-022): py/tarslip
# ============================================================================

def is_unsafe_tar_slip(state) -> bool:
    """
    Check if state is in unsafe region for tar slip attack.
    
    Unsafe region:
    U_tarslip := { s | π == π_tar_extract ∧ τ(tar_source) == 1 ∧ ¬PathValidated(member) }
    
    Detection requires:
    - At tarfile extraction site
    - Tar source is tainted
    - Member paths not validated for traversal
    """
    return getattr(state, 'tar_slip_detected', False)


def extract_tar_slip_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for tar slip vulnerability."""
    return {
        "bug_type": "TAR_SLIP",
        "cwe": "CWE-022",
        "query_id": "py/tarslip",
        "description": "Arbitrary file write during tarfile extraction",
        "trace": trace,
        "extraction_site": getattr(state, 'tar_slip_site', None),
        "tainted_source": getattr(state, 'tar_slip_source', None),
        "mitigation": "Validate member paths before extraction, use tarfile.extractall with filter"
    }


# ============================================================================
# JINJA2_AUTOESCAPE_FALSE (CWE-079): py/jinja2/autoescape-false
# ============================================================================

def is_unsafe_jinja2_autoescape_false(state) -> bool:
    """
    Check if state is in unsafe region for Jinja2 autoescape disabled.
    
    Unsafe region:
    U_jinja := { s | π == π_jinja_env ∧ autoescape == False ∧ τ(template_input) == 1 }
    """
    return getattr(state, 'jinja2_autoescape_false_detected', False)


def extract_jinja2_autoescape_false_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for Jinja2 autoescape disabled."""
    return {
        "bug_type": "JINJA2_AUTOESCAPE_FALSE",
        "cwe": "CWE-079",
        "query_id": "py/jinja2/autoescape-false",
        "description": "Jinja2 template with autoescape=False",
        "trace": trace,
        "env_site": getattr(state, 'jinja2_site', None),
        "mitigation": "Set autoescape=True in Jinja2 Environment"
    }
