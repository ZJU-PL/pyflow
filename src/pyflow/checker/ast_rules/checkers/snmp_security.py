"""
B510: Test for insecure SNMP configuration.

Using default or weak SNMP community strings exposes
device configuration to unauthorized access.
"""

from ...common import issue
from ..core import test_properties as test
from ..core.utils import get_call_name
import ast

DEFAULT_COMMUNITY_STRINGS = {
    "public",
    "private",
    "community",
    "snmp",
    "admin",
    "default",
}


@test.checks("Str")
@test.with_id("B510")
def snmp_weak_community(context):
    s = context.string
    if not isinstance(s, str):
        return None
    parent = getattr(context.node, "_bandit_parent", None)
    if isinstance(parent, ast.keyword):
        parent = getattr(parent, "_bandit_parent", None)
    if not isinstance(parent, ast.Call):
        return None
    call_name = get_call_name(parent, context.import_aliases or {})
    if call_name not in {
        "pysnmp.hlapi.CommunityData",
        "pysnmp.hlapi.v1arch.CommunityData",
        "pysnmp.hlapi.v3arch.CommunityData",
    }:
        return None
    # CommunityData(communityName), or CommunityData(index, communityName).
    community = parent.args[1] if len(parent.args) > 1 else parent.args[0] if parent.args else None
    for keyword in parent.keywords:
        if keyword.arg == "communityName":
            community = keyword.value
    if community is not context.node:
        return None
    if s.lower() in DEFAULT_COMMUNITY_STRINGS:
        return issue.Issue(
            severity="HIGH",
            confidence="HIGH",
            cwe=issue.Cwe.WEAK_CREDENTIALS,
            text="Default SNMP community string detected: '{}'. "
            "Default SNMP community strings are widely known and "
            "allow unauthorized device access. Use a strong, "
            "unique community string.".format(s),
        )
    return None


@test.checks("Call")
@test.with_id("B511")
def snmp_insecure_version(context):
    qualname = context.call_function_name_qual
    if qualname in {
        "pysnmp.hlapi.getCmd",
        "pysnmp.hlapi.setCmd",
        "pysnmp.hlapi.nextCmd",
        "pysnmp.hlapi.bulkCmd",
    }:
        return issue.Issue(
            severity="MEDIUM",
            confidence="MEDIUM",
            cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
            text="SNMP v1/v2c command detected. SNMP v1 and v2c "
            "transmit community strings in cleartext and provide "
            "no encryption. Use SNMPv3 with authentication and privacy.",
        )
    return None
