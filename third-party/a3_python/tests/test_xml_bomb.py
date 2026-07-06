"""
Tests for XML_BOMB (CWE-776) detection - XML entity expansion attacks.

XML_BOMB is a denial-of-service attack where malicious XML contains
entity definitions that expand exponentially (billion laughs attack).

Unsafe region: U_xmlbomb := { s | π == π_xml_parse ∧ τ(xml_input) == 1 }

The detector checks for untrusted data being parsed by XML libraries
without entity expansion protection.
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.contracts.security_lattice import (
    check_sink_taint, get_sink_contracts,
    init_security_contracts, apply_sanitizer,
)


@pytest.fixture(autouse=True)
def setup_contracts():
    """Initialize security contracts before each test."""
    init_security_contracts()


def test_xml_bomb_elementtree_parse_untrusted():
    """BUG: Untrusted XML parsed with ElementTree.parse"""
    # Tainted XML from user input
    xml_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "request.data")
    
    # Check sink for ElementTree.parse
    contracts = get_sink_contracts("xml.etree.ElementTree.parse")
    xml_bomb_contracts = [c for c in contracts if c.bug_type == "XML_BOMB"]
    assert len(xml_bomb_contracts) > 0, "Expected XML_BOMB contract for ElementTree.parse"
    
    # Check violation
    violations = check_sink_taint(
        "xml.etree.ElementTree.parse",
        location="<test>:1",
        arg_labels=[xml_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) > 0, "Expected XML_BOMB violation for tainted XML"


def test_xml_bomb_elementtree_fromstring_untrusted():
    """BUG: Untrusted XML parsed with ElementTree.fromstring"""
    xml_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "xml_string")
    
    contracts = get_sink_contracts("xml.etree.ElementTree.fromstring")
    xml_bomb_contracts = [c for c in contracts if c.bug_type == "XML_BOMB"]
    assert len(xml_bomb_contracts) > 0
    
    violations = check_sink_taint(
        "xml.etree.ElementTree.fromstring",
        location="<test>:1",
        arg_labels=[xml_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) > 0


def test_xml_bomb_lxml_parse_untrusted():
    """BUG: Untrusted XML parsed with lxml.etree.parse"""
    xml_label = TaintLabel.from_untrusted_source(SourceType.FILE_CONTENT, "uploaded_file")
    
    contracts = get_sink_contracts("lxml.etree.parse")
    xml_bomb_contracts = [c for c in contracts if c.bug_type == "XML_BOMB"]
    assert len(xml_bomb_contracts) > 0
    
    violations = check_sink_taint(
        "lxml.etree.parse",
        location="<test>:1",
        arg_labels=[xml_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) > 0


def test_xml_bomb_minidom_parsestring_untrusted():
    """BUG: Untrusted XML parsed with minidom.parseString"""
    xml_label = TaintLabel.from_untrusted_source(SourceType.NETWORK_RECV, "socket_data")
    
    contracts = get_sink_contracts("xml.dom.minidom.parseString")
    xml_bomb_contracts = [c for c in contracts if c.bug_type == "XML_BOMB"]
    assert len(xml_bomb_contracts) > 0
    
    violations = check_sink_taint(
        "xml.dom.minidom.parseString",
        location="<test>:1",
        arg_labels=[xml_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) > 0


def test_xml_bomb_sax_parse_untrusted():
    """BUG: Untrusted XML parsed with SAX parser"""
    xml_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "xml_input")
    
    contracts = get_sink_contracts("xml.sax.parseString")
    xml_bomb_contracts = [c for c in contracts if c.bug_type == "XML_BOMB"]
    assert len(xml_bomb_contracts) > 0
    
    violations = check_sink_taint(
        "xml.sax.parseString",
        location="<test>:1",
        arg_labels=[xml_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) > 0


def test_xml_bomb_trusted_xml_safe():
    """NON-BUG: Trusted/sanitized XML is safe"""
    # Clean XML from internal constant
    clean_label = TaintLabel.clean()
    
    violations = check_sink_taint(
        "xml.etree.ElementTree.parse",
        location="<test>:1",
        arg_labels=[clean_label],
    )
    
    xml_bomb_violations = [v for v in violations if v.bug_type == "XML_BOMB"]
    assert len(xml_bomb_violations) == 0, "Clean XML should not trigger XML_BOMB"


def test_xml_bomb_taint_label_properties():
    """Verify that XML_BOMB detection uses correct taint properties"""
    # Create tainted XML
    xml_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "xml_data")
    
    # Should have untrusted taint
    assert xml_label.has_untrusted_taint()
    
    # Should NOT be safe for XML_PARSE sink initially  
    assert not xml_label.is_safe_for_sink(SinkType.XML_PARSE)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
