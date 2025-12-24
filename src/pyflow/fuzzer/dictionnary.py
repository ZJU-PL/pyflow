"""
Fuzzing Dictionary for Interesting Keywords/Tokens.

This module provides a Dictionary class for loading and using a dictionary
of interesting keywords or tokens during fuzzing. The dictionary can help
guide mutations by providing known-interesting values (e.g., magic numbers,
keywords, common strings).

**Dictionary Format:**
The dictionary file is a text file with one entry per line:
- Lines starting with '#' are comments
- Entries are strings in double quotes: "keyword"
- Empty lines are ignored

**Example Dictionary:**
```
# Common magic numbers
"0xDEADBEEF"
"0xCAFEBABE"
# Common keywords
"password"
"admin"
```

**Usage:**
The dictionary is optional. If provided, it can be used by mutation
strategies to replace values with dictionary entries, potentially
finding bugs that depend on specific keywords or values.
"""

import random
import re
import os

class Dictionary:
    """
    Dictionary of interesting keywords/tokens for fuzzing.
    
    Loads a dictionary from a file and provides random access to entries.
    The dictionary format is similar to AFL/libFuzzer dictionaries.
    
    Attributes:
        _dict: List of dictionary entries (strings)
    """
    # Regular expression to match dictionary entries: "string"
    line_re = re.compile('"(.+)"$')

    def __init__(self, dict_path=None):
        """
        Initialize a dictionary from a file.
        
        Args:
            dict_path: Path to dictionary file (optional).
                      If None or file doesn't exist, creates empty dictionary.
        """
        if not dict_path or not os.path.exists(dict_path):
            self._dict = list()
            return

        # Load dictionary entries from file
        _dict = set()  # Use set to avoid duplicates
        with open(dict_path) as f:
            for line in f:
                line = line.lstrip()
                # Skip comments and empty lines
                if line.startswith('#'):
                    continue
                # Extract quoted strings
                word = self.line_re.search(line)
                if word:
                    _dict.add(word.group(1))
        self._dict = list(_dict)

    def get_word(self):
        """
        Get a random word from the dictionary.
        
        Returns:
            Random dictionary entry, or None if dictionary is empty
        """
        if not self._dict:
            return None
        return random.choice(self._dict)
