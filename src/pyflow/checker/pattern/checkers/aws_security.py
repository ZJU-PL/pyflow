"""
AWS SDK Security Checks.

Detects AWS-specific security misconfigurations and vulnerabilities.

Test IDs:
- W101: Hardcoded AWS credentials
- W102: S3 bucket public read/write
- W103: EC2 with public IP
- W104: RDS publicly accessible
- W105: Overly permissive IAM policy
- W106: Missing encryption at rest
- W107: Secrets not in Secrets Manager
- W108: Using default/bad region
- W109: STS assume role without external ID
- W110: Security group with open ports
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test


AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
AWS_SECRET_KEY_RE = re.compile(
    r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]"
)
PUBLIC_ACL_RE = re.compile(r"(?i)public[_-]?(read|write|full)")


def _aws_issue(text, severity="HIGH", confidence="MEDIUM", cwe=None):
    cwe_id = cwe if cwe else issue.Cwe.NOTSET
    return issue.Issue(
        severity=severity,
        confidence=confidence,
        cwe=cwe_id,
        text=text,
    )


def _get_string_value(node):
    """Extract string value from AST node."""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_strings(node):
    """Collect all string literals from a node subtree."""
    strings = []
    for child in ast.walk(node):
        value = _get_string_value(child)
        if value is not None:
            strings.append(value)
    return strings


@test.checks("Assign")
@test.with_id("W101")
def hardcoded_aws_credentials(context):
    """Detect hardcoded AWS access keys or secret keys."""
    strings = _collect_strings(context.node.value)
    for s in strings:
        if AWS_ACCESS_KEY_RE.search(s) or AWS_SECRET_KEY_RE.search(s):
            return _aws_issue(
                "Hardcoded AWS credentials detected - use environment variables or IAM roles instead.",
                confidence="HIGH",
                cwe=issue.Cwe.HARDCODED_SECRET,
            )
    return None


@test.checks("Call")
@test.with_id("W102")
def s3_public_access(context):
    """Detect S3 bucket configuration with public access."""
    qual = context.call_function_name_qual or ""
    if "Bucket" in qual or "Object" in qual:
        for kw in context.node.keywords:
            if kw.arg in ("ACL", "PublicRead", "PublicWrite"):
                value = _get_string_value(kw.value) or ""
                if PUBLIC_ACL_RE.search(str(value)):
                    return _aws_issue(
                        "S3 bucket/object with public ACL may allow unauthorized access.",
                        confidence="HIGH",
                        cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                    )
    return None


@test.checks("Call")
@test.with_id("W103")
def ec2_public_ip(context):
    """Detect EC2 instance with public IP assignment."""
    qual = context.call_function_name_qual or ""
    if "Instance" in qual or "create_instances" in qual:
        for kw in context.node.keywords:
            if kw.arg in ("AssociatePublicIpAddress", "PublicIp"):
                return _aws_issue(
                    "EC2 instance with public IP may be directly accessible from the internet.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                )
    return None


@test.checks("Call")
@test.with_id("W104")
def rds_publicly_accessible(context):
    """Detect RDS instance configured for public access."""
    qual = context.call_function_name_qual or ""
    if "DBInstance" in qual or "create_db_instance" in qual:
        for kw in context.node.keywords:
            if kw.arg == "PubliclyAccessible":
                return _aws_issue(
                    "RDS instance with public accessibility may expose database to the internet.",
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                )
    return None


@test.checks("Assign")
@test.with_id("W107")
def secrets_not_in_secrets_manager(context):
    """Detect secrets hardcoded instead of using AWS Secrets Manager."""
    if not hasattr(context.node, "value"):
        return None
    strings = _collect_strings(context.node.value)
    for s in strings:
        if any(
            secret in s.lower()
            for secret in ("password", "secret", "api_key", "credential")
        ):
            if not ("secretsmanager" in s.lower() or "secretmanager" in s.lower()):
                return _aws_issue(
                    "Possible hardcoded secret detected - use AWS Secrets Manager for sensitive values.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.HARDCODED_SECRET,
                )
    return None


@test.checks("Call")
@test.with_id("W106")
def missing_encryption_at_rest(context):
    """Detect missing encryption configuration for AWS resources."""
    qual = context.call_function_name_qual or ""
    encryption_args = ("Encrypted", "EnableEncryption", "ServerSideEncryption")
    if any(res in qual for res in ("Bucket", "Instance", "Volume", "DBInstance")):
        has_encryption = False
        for kw in context.node.keywords:
            if kw.arg in encryption_args:
                has_encryption = True
                break
        if not has_encryption:
            return _aws_issue(
                f"Resource created without explicit encryption configuration - enable encryption at rest.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
            )
    return None


@test.checks("Call")
@test.with_id("W108")
def default_or_bad_region(context):
    """Detect usage of default or potentially incorrect AWS region."""
    qual = context.call_function_name_qual or ""
    if "client" in qual.lower() or "resource" in qual.lower():
        has_region = False
        for kw in context.node.keywords:
            if kw.arg == "region_name":
                has_region = True
                region = _get_string_value(kw.value)
                if region in ("us-east-1", None):
                    return _aws_issue(
                        "Consider specifying an explicit AWS region for resource creation.",
                        severity="LOW",
                        confidence="LOW",
                    )
        if not has_region:
            return _aws_issue(
                "No AWS region specified - may use default region unexpectedly.",
                severity="LOW",
                confidence="LOW",
            )
    return None


@test.checks("Call")
@test.with_id("W109")
def sts_assume_role_no_external_id(context):
    """Detect STS assume_role call without ExternalId parameter."""
    qual = context.call_function_name_qual or ""
    if "assume_role" in qual.lower():
        has_external_id = False
        for kw in context.node.keywords:
            if kw.arg == "ExternalId":
                has_external_id = True
                break
        if not has_external_id:
            return _aws_issue(
                "STS assume_role without ExternalId may allow unintended role chaining.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            )
    return None


@test.checks("Call")
@test.with_id("W110")
def security_group_open_ports(context):
    """Detect security group with overly permissive port ranges."""
    qual = context.call_function_name_qual or ""
    if "SecurityGroup" in qual or "authorize_ingress" in qual:
        for kw in context.node.keywords:
            if kw.arg in ("IpPermissions", "FromPort", "ToPort"):
                return _aws_issue(
                    "Security group ingress rule may expose wide port range - restrict to necessary ports.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                )
    return None
