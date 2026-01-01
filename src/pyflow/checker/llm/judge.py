"""
LLM-based bug report judge for analyzing and categorizing security issues.
Independent from pyflow framework.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .llm_utils import LLMClient, LLMConfig, format_bug_report, retry_llm_call


@dataclass
class BugJudgment:
    """Result of bug report analysis."""

    is_security_issue: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_id: Optional[str]
    confidence: float
    category: str  # e.g., "Injection", "Authentication", "Authorization"
    explanation: str
    remediation: str


class BugReportJudge:
    """LLM-powered judge for analyzing bug reports."""

    def __init__(self, llm_config: LLMConfig):
        self.llm_client = LLMClient(llm_config)
        self.judge_prompt = """
        Analyze this bug report and determine if it's a security vulnerability:

        {bug_report}

        Respond with JSON in this exact format:
        {
            "is_security_issue": boolean,
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "cwe_id": "CWE-XXX or null",
            "confidence": 0.0-1.0,
            "category": "brief category name",
            "explanation": "why this is/isn't a security issue",
            "remediation": "how to fix or mitigate"
        }

        Be precise and focus only on security implications.
        """

    @retry_llm_call(max_retries=2)
    def judge_report(self, bug_report: Dict[str, Any]) -> BugJudgment:
        """Analyze a bug report and return judgment."""
        formatted_report = format_bug_report(bug_report)

        prompt = self.judge_prompt.format(bug_report=formatted_report)

        response = self.llm_client.call_simple(prompt)

        try:
            # Parse JSON response
            result = self._parse_judgment_response(response)

            return BugJudgment(
                is_security_issue=result["is_security_issue"],
                severity=result["severity"],
                cwe_id=result["cwe_id"],
                confidence=result["confidence"],
                category=result["category"],
                explanation=result["explanation"],
                remediation=result["remediation"],
            )
        except (ValueError, KeyError) as e:
            # Fallback judgment if parsing fails
            return BugJudgment(
                is_security_issue=False,
                severity="LOW",
                cwe_id=None,
                confidence=0.5,
                category="Unknown",
                explanation=f"Failed to parse LLM response: {e}",
                remediation="Manual review required",
            )

    def judge_reports_batch(
        self, bug_reports: List[Dict[str, Any]]
    ) -> List[BugJudgment]:
        """Analyze multiple bug reports in batch."""
        return [self.judge_report(report) for report in bug_reports]

    def _parse_judgment_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from LLM."""
        # Find JSON in response (LLM might add extra text)
        import json
        import re

        json_match = re.search(r"\{.*\}", response, re.DOTALL)
        if not json_match:
            raise ValueError("No JSON found in response")

        return json.loads(json_match.group())

    def is_false_positive(
        self, bug_report: Dict[str, Any], threshold: float = 0.7
    ) -> bool:
        """Quick check if report is likely a false positive."""
        judgment = self.judge_report(bug_report)
        return not judgment.is_security_issue and judgment.confidence > threshold
