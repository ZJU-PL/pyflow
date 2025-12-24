"""
Security Issue Representation.

This module provides classes for representing security issues found during
code analysis. Issues include information about severity, confidence, CWE
(Common Weakness Enumeration) identifiers, and location information.

**Issue Lifecycle:**
1. Created by security tests when vulnerabilities are detected
2. Annotated with file and location information by the visitor
3. Filtered based on severity/confidence thresholds
4. Formatted for output (text, JSON, SARIF, etc.)

**CWE Integration:**
CWE (Common Weakness Enumeration) provides standardized identifiers for
security weaknesses. Each issue can be associated with one or more CWE IDs
to categorize the type of vulnerability.
"""

import linecache


class Cwe:
    """
    Common Weakness Enumeration (CWE) identifier.
    
    CWE is a community-developed list of software and hardware weakness types.
    Each CWE ID represents a specific type of security weakness. This class
    provides CWE constants and utilities for generating CWE links.
    
    **CWE Categories:**
    - Input Validation (CWE-20, CWE-22)
    - Injection (CWE-78, CWE-79, CWE-89, CWE-94)
    - Cryptography (CWE-259, CWE-295, CWE-326, CWE-327)
    - Access Control (CWE-284, CWE-732)
    - And many more...
    
    Attributes:
        id: CWE identifier (0 = NOTSET)
    """
    NOTSET = 0
    IMPROPER_INPUT_VALIDATION = 20
    PATH_TRAVERSAL = 22
    OS_COMMAND_INJECTION = 78
    XSS = 79
    BASIC_XSS = 80
    SQL_INJECTION = 89
    CODE_INJECTION = 94
    IMPROPER_WILDCARD_NEUTRALIZATION = 155
    HARD_CODED_PASSWORD = 259
    IMPROPER_ACCESS_CONTROL = 284
    IMPROPER_CERT_VALIDATION = 295
    CLEARTEXT_TRANSMISSION = 319
    INADEQUATE_ENCRYPTION_STRENGTH = 326
    BROKEN_CRYPTO = 327
    INSUFFICIENT_RANDOM_VALUES = 330
    INSECURE_TEMP_FILE = 377
    UNCONTROLLED_RESOURCE_CONSUMPTION = 400
    DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK = 494
    DESERIALIZATION_OF_UNTRUSTED_DATA = 502
    MULTIPLE_BINDS = 605
    IMPROPER_CHECK_OF_EXCEPT_COND = 703
    INCORRECT_PERMISSION_ASSIGNMENT = 732
    INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT = 838

    MITRE_URL_PATTERN = "https://cwe.mitre.org/data/definitions/%s.html"

    def __init__(self, id=NOTSET):
        """
        Initialize a CWE identifier.
        
        Args:
            id: CWE ID (default: NOTSET = 0)
        """
        self.id = id

    def link(self):
        """
        Get the MITRE CWE URL for this CWE ID.
        
        Returns:
            URL string, or empty string if NOTSET
        """
        return "" if self.id == Cwe.NOTSET else Cwe.MITRE_URL_PATTERN % str(self.id)

    def __str__(self):
        """String representation: CWE-ID (URL)"""
        return "" if self.id == Cwe.NOTSET else "CWE-%i (%s)" % (self.id, self.link())

    def as_dict(self):
        """
        Convert to dictionary for JSON output.
        
        Returns:
            Dictionary with id and link, or empty dict if NOTSET
        """
        return {"id": self.id, "link": self.link()} if self.id != Cwe.NOTSET else {}

    def __eq__(self, other):
        """Equality based on CWE ID."""
        return self.id == other.id

    def __ne__(self, other):
        """Inequality based on CWE ID."""
        return self.id != other.id

    def __hash__(self):
        """Hash based on object identity."""
        return id(self)


class Issue:
    """
    Represents a security issue found in code.
    
    An Issue contains all information about a security vulnerability or
    weakness detected during code analysis, including:
    - Severity and confidence levels
    - CWE classification
    - Location information (file, line, column)
    - Test information (which test found it)
    - Issue description
    
    **Severity Levels:**
    - HIGH: Critical security issues
    - MEDIUM: Significant security concerns
    - LOW: Minor security issues
    - UNDEFINED: Unspecified severity
    
    **Confidence Levels:**
    - HIGH: Very confident the issue is real
    - MEDIUM: Moderately confident
    - LOW: Low confidence (may be false positive)
    - UNDEFINED: Unspecified confidence
    
    Attributes:
        severity: Severity level (HIGH, MEDIUM, LOW, UNDEFINED)
        cwe: CWE identifier object
        confidence: Confidence level
        text: Human-readable issue description
        ident: Identifier (e.g., function/import name that triggered issue)
        fname: Filename where issue was found
        fdata: File data object (for reading source code)
        test: Test name that found the issue
        test_id: Test ID (e.g., "B301")
        lineno: Line number where issue occurs
        col_offset: Column offset where issue starts
        end_col_offset: Column offset where issue ends
        linerange: Range of lines affected
    """
    def __init__(self, severity, cwe=0, confidence="UNDEFINED", text="", ident=None, 
                 lineno=None, test_id="", col_offset=-1, end_col_offset=0):
        """
        Initialize a security issue.
        
        Args:
            severity: Severity level (HIGH, MEDIUM, LOW, UNDEFINED)
            cwe: CWE ID (default: 0 = NOTSET)
            confidence: Confidence level (default: UNDEFINED)
            text: Issue description text
            ident: Identifier that triggered the issue
            lineno: Line number (default: None, will be filled from context)
            test_id: Test ID (e.g., "B301")
            col_offset: Column offset (default: -1, will be filled from context)
            end_col_offset: End column offset (default: 0)
        """
        self.severity = severity
        self.cwe = Cwe(cwe)
        self.confidence = confidence
        self.text = text.decode("utf-8") if isinstance(text, bytes) else text
        self.ident = ident
        self.fname = ""
        self.fdata = None
        self.test = ""
        self.test_id = test_id
        self.lineno = lineno
        self.col_offset = col_offset
        self.end_col_offset = end_col_offset
        self.linerange = []

    def __str__(self):
        return ("Issue: '%s' from %s:%s: CWE: %s, Severity: %s Confidence: %s at %s:%i:%i") % (
            self.text, self.test_id, (self.ident or self.test), str(self.cwe),
            self.severity, self.confidence, self.fname, self.lineno, self.col_offset)

    def __eq__(self, other):
        match_fields = ["text", "severity", "cwe", "confidence", "fname", "test", "test_id"]
        return all(getattr(self, field) == getattr(other, field) for field in match_fields)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(self)

    def filter(self, severity, confidence):
        """
        Check if issue meets severity and confidence thresholds.
        
        An issue passes the filter if its severity and confidence are
        both >= the specified thresholds (using RANKING ordering).
        
        Args:
            severity: Minimum severity threshold
            confidence: Minimum confidence threshold
            
        Returns:
            True if issue meets thresholds, False otherwise
        """
        from .constants import RANKING
        return (RANKING.index(self.severity) >= RANKING.index(severity) and 
                RANKING.index(self.confidence) >= RANKING.index(confidence))

    def get_code(self, max_lines=3, tabbed=False):
        """
        Get source code lines around the issue location.
        
        Retrieves code from the file to provide context for the issue.
        Includes lines before and after the issue location.
        
        Args:
            max_lines: Maximum number of lines to include
            tabbed: Whether to use tab-separated format (line number + code)
            
        Returns:
            String containing formatted code lines
        """
        max_lines = max(max_lines, 1)
        lmin = max(1, self.lineno - max_lines // 2)
        lmax = lmin + len(self.linerange) + max_lines - 1

        # Handle stdin (file data object) vs regular files
        if self.fname == "<stdin>":
            self.fdata.seek(0)
            for _ in range(1, lmin):
                self.fdata.readline()

        tmplt = "%i\t%s" if tabbed else "%i %s"
        lines = []
        for line in range(lmin, lmax):
            text = self.fdata.readline() if self.fname == "<stdin>" else linecache.getline(self.fname, line)
            if not text:
                break
            if isinstance(text, bytes):
                text = text.decode("utf-8")
            lines.append(tmplt % (line, text))
        return "".join(lines)

    def as_dict(self, with_code=True, max_lines=3):
        """
        Convert the issue to a dictionary for JSON output.
        
        Args:
            with_code: Whether to include source code in output
            max_lines: Maximum lines of code to include
            
        Returns:
            Dictionary representation of the issue
        """
        out = {
            "filename": self.fname, "test_name": self.test, "test_id": self.test_id,
            "issue_severity": self.severity, "issue_cwe": self.cwe.as_dict(),
            "issue_confidence": self.confidence, "issue_text": self.text,
            "line_number": self.lineno, "line_range": self.linerange,
            "col_offset": self.col_offset, "end_col_offset": self.end_col_offset,
        }
        if with_code:
            out["code"] = self.get_code(max_lines=max_lines)
        return out
