"""
Security Checker Constants.

This module defines constants used throughout the security checker,
including severity/confidence rankings, default values, and exclusion patterns.

**Ranking System:**
The checker uses a ranking system for both severity and confidence:
- UNDEFINED: Lowest level (1 point)
- LOW: Low level (3 points)
- MEDIUM: Medium level (5 points)
- HIGH: Highest level (10 points)

**Scoring:**
Issues are scored based on their severity and confidence levels.
Higher scores indicate more serious or more certain issues.
"""

# Security checker constants

# Ranking levels ordered from lowest to highest
RANKING = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"]

# Point values for each ranking level (used in scoring)
RANKING_VALUES = {"UNDEFINED": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 10}

# Default criteria for filtering (severity and confidence thresholds)
CRITERIA = [("SEVERITY", "UNDEFINED"), ("CONFIDENCE", "UNDEFINED")]

# Add each ranking to globals for direct access (e.g., HIGH, MEDIUM, etc.)
for rank in RANKING:
    globals()[rank] = rank

# Default confidence level when not specified
CONFIDENCE_DEFAULT = "UNDEFINED"

# Values that Python considers to be False (for boolean checks in tests)
FALSE_VALUES = [None, False, "False", 0, 0.0, 0j, "", (), [], {}]

# Directories to exclude by default during file scanning
# These are typically version control directories, build artifacts, etc.
EXCLUDE = (
    ".svn",      # Subversion
    "CVS",       # CVS version control
    ".bzr",      # Bazaar
    ".hg",       # Mercurial
    ".git",      # Git
    "__pycache__",  # Python bytecode cache
    ".tox",      # Tox virtual environments
    ".eggs",     # Python eggs
    "*.egg",     # Python egg files
)
