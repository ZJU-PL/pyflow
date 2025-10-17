"""
LLM-native security vulnerability checker.
Analyzes code using LLM for comprehensive security vulnerability detection.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .llm_utils import LLMClient, LLMConfig, format_code_snippet, retry_llm_call


@dataclass
class SecurityFinding:
    """Security vulnerability finding from LLM analysis."""
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_id: str
    confidence: float
    line_number: Optional[int]
    description: str
    remediation: str
    evidence: str


class LLMSecurityChecker:
    """LLM-powered security vulnerability detector."""

    def __init__(self, llm_config: LLMConfig):
        self.llm_client = LLMClient(llm_config)
        self.security_prompt = """
        Analyze this Python code for security vulnerabilities:

        {code}

        Look for:
        1. Injection attacks (SQL, command, etc.)
        2. Authentication/authorization bypass
        3. Cryptographic weaknesses
        4. Input validation issues
        5. Information disclosure
        6. Race conditions
        7. Insecure deserialization
        8. XSS/CSRF vulnerabilities
        9. Insecure random number generation
        10. Hardcoded secrets

        Respond with JSON array of vulnerabilities in this exact format:
        [
            {{
                "vulnerability_type": "type name",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW",
                "cwe_id": "CWE-XXX",
                "confidence": 0.0-1.0,
                "line_number": number_or_null,
                "description": "what's vulnerable and why",
                "remediation": "how to fix",
                "evidence": "specific code snippet showing the issue"
            }}
        ]

        Only include vulnerabilities you're confident about (confidence > 0.6).
        Return empty array if no vulnerabilities found.
        """

    @retry_llm_call(max_retries=2)
    def analyze_code(self, code: str, file_path: str = "") -> List[SecurityFinding]:
        """Analyze code for security vulnerabilities using LLM."""
        formatted_code = format_code_snippet(code, "python")

        prompt = self.security_prompt.format(code=formatted_code)
        response = self.llm_client.call_simple(prompt)

        try:
            findings = self._parse_security_response(response)
            return [SecurityFinding(**finding) for finding in findings]
        except (ValueError, KeyError):
            return []

    def _parse_security_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse JSON response from LLM for security findings."""
        import json
        import re

        # Extract JSON array from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if not json_match:
            return []

        return json.loads(json_match.group())

    def analyze_file(self, file_path: str) -> List[SecurityFinding]:
        """Analyze a complete file for security vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.analyze_code(code, file_path)
        except Exception:
            return []

    def analyze_snippet(self, code_snippet: str, context_lines: int = 5) -> List[SecurityFinding]:
        """Analyze a code snippet with surrounding context."""
        return self.analyze_code(code_snippet)
