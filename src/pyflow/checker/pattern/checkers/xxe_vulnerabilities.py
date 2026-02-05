# Check for XXE (XML External Entity) vulnerabilities
import ast

from ..core import issue
from ..core import test_properties as test


def xxe_issue():
    """Create an XXE vulnerability issue"""
    return issue.Issue(
        severity="HIGH",
        confidence="HIGH",
        cwe=issue.Cwe.XXE,
        text="XML parsing with entity resolution enabled - vulnerable to XXE attack.",
    )


def _check_parser_has_dtd_or_entity_resolution(call_node):
    """Check if parser configuration enables DTD or entity resolution"""
    # Check keyword arguments
    for keyword in call_node.keywords:
        if keyword.arg:
            arg_lower = keyword.arg.lower()
            # Check for dangerous settings
            if arg_lower in ('load_dtd', 'dtd_loader', 'resolve_entities',
                            'entity_resolution', 'no_network', 'dtd_validation'):
                # Get the value - check if it's True (dangerous) or False (safe)
                if isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        return True
    return False


@test.checks("Call")
@test.with_id("B301")
def lxml_parser_dtd_enabled(context):
    """Check for lxml XMLParser with DTD loading enabled"""
    if context.call_function_name_qual in ["lxml.etree.XMLParser", "etree.XMLParser"]:
        call_node = context.node
        if call_node and _check_parser_has_dtd_or_entity_resolution(call_node):
            return xxe_issue()


@test.checks("Call")
@test.with_id("B302")
def lxml_html_parser_entity_sub(context):
    """Check for lxml HTMLParser with entity substitution"""
    if context.call_function_name_qual in ["lxml.etree.HTMLParser", "etree.HTMLParser"]:
        call_node = context.node
        # HTMLParser may have different dangerous parameters
        for keyword in call_node.keywords:
            if keyword.arg and keyword.arg.lower() in ('entity_substitution',):
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return xxe_issue()


@test.checks("Call")
@test.with_id("B303")
def lxml_fromstring_with_dangerous_parser(context):
    """Check for lxml fromstring with dangerous parser configuration"""
    if context.call_function_name_qual in ["lxml.etree.fromstring", "etree.fromstring"]:
        call_node = context.node
        # Check if parser is passed as second argument with dangerous config
        if len(call_node.args) >= 2:
            parser_arg = call_node.args[1]
            if isinstance(parser_arg, ast.Call):
                if parser_arg.func.attr in ['XMLParser', 'HTMLParser']:
                    if _check_parser_has_dtd_or_entity_resolution(parser_arg):
                        return xxe_issue()


@test.checks("Call")
@test.with_id("B304")
def xml_dom_minidom_parse(context):
    """Check for xml.dom.minidom parsing (can expand entities)"""
    if context.call_function_name_qual in ["xml.dom.minidom.parse", "xml.dom.minidom.parseString"]:
        # minidom can expand entities by default
        return xxe_issue()


@test.checks("Call")
@test.with_id("B305")
def xml_sax_parse_string(context):
    """Check for xml.sax.parseString (can enable entity resolution)"""
    if context.call_function_name_qual == "xml.sax.parseString":
        call_node = context.node
        # xml.sax doesn't have easy ways to disable entity resolution
        return xxe_issue()


@test.checks("Call")
@test.with_id("B306")
def expat_parser_create(context):
    """Check for xml.parsers.expat.ParserCreate without safety measures"""
    if context.call_function_name_qual == "xml.parsers.expat.ParserCreate":
        call_node = context.node
        # ParserCreate returns a parser - we can't easily check its configuration
        # but this is a potential warning point
        for keyword in call_node.keywords:
            if keyword.arg and keyword.arg.lower() in ('namespace_separator',):
                return xxe_issue()


@test.checks("Call")
@test.with_id("B307")
def defusedxml_lxml_safe(context):
    """Check for safe defusedxml lxml usage (should NOT flag)"""
    if context.call_function_name_qual and context.call_function_name_qual.startswith("defusedxml.lxml"):
        # defusedxml is the safe alternative - skip these
        pass


@test.checks("Call")
@test.with_id("B308")
def lxml_xmlschema_validation(context):
    """Check for lxml XMLSchema validation that loads external resources"""
    if context.call_function_name_qual in ["lxml.etree.XMLSchema", "etree.XMLSchema"]:
        call_node = context.node
        # XMLSchema loading can fetch external DTDs
        if len(call_node.args) >= 1:
            schema_source = call_node.args[0]
            # If loading from file/string that could contain external refs
            return xxe_issue()


@test.checks("Call")
@test.with_id("B309")
def lxml_xslt_transformation(context):
    """Check for lxml XSLT transformation (can load external resources)"""
    if context.call_function_name_qual in ["lxml.etree.XSLT", "etree.XSLT"]:
        call_node = context.node
        # XSLT can load external documents
        return xxe_issue()


@test.checks("Call")
@test.with_id("B310")
def sax_parser_create(context):
    """Check for xml.sax.saxparser creating parser without safety"""
    if context.call_function_name_qual == "xml.sax.saxparser":
        return xxe_issue()
