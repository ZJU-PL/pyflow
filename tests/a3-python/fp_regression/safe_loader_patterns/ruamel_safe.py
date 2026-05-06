"""
FP Regression Test: ruamel.yaml safe loading.

ruamel.yaml with typ='safe' or typ='rt' (round-trip) is safe.
These should NOT be flagged as YAML_INJECTION.

Expected: NO FINDINGS
"""

# Note: This test may not run without ruamel.yaml installed,
# but the analyzer should still recognize the pattern.

try:
    from ruamel.yaml import YAML
    HAS_RUAMEL = True
except ImportError:
    HAS_RUAMEL = False
    # Mock for static analysis
    class YAML:
        def __init__(self, typ='rt', **kwargs):
            self.typ = typ
        def load(self, stream):
            pass
        def dump(self, data, stream):
            pass


def load_ruamel_safe():
    """Load with ruamel.yaml safe mode - should NOT flag."""
    
    yaml = YAML(typ='safe')  # Explicit safe mode
    
    content = "name: test\nvalue: 123"
    
    from io import StringIO
    data = yaml.load(StringIO(content))  # Should NOT flag
    
    return data


def load_ruamel_roundtrip():
    """Load with ruamel.yaml round-trip mode - should NOT flag.
    
    Round-trip ('rt') mode preserves comments and formatting.
    It is ALSO safe against arbitrary code execution.
    """
    
    yaml = YAML()  # Default is typ='rt' (round-trip)
    # Equivalent to: yaml = YAML(typ='rt')
    
    content = """
    # Configuration file
    name: myapp
    version: 1.0
    """
    
    from io import StringIO
    data = yaml.load(StringIO(content))  # Should NOT flag
    
    return data


def load_ruamel_pure():
    """Load with ruamel.yaml pure Python mode - should NOT flag.
    
    Pure mode uses pure Python implementation.
    """
    
    yaml = YAML(typ='safe', pure=True)
    
    content = "test: value"
    
    from io import StringIO
    data = yaml.load(StringIO(content))  # Should NOT flag
    
    return data


# CONTRAST: This WOULD be unsafe but ruamel.yaml doesn't have an "unsafe" typ
# by default - unlike PyYAML, ruamel.yaml is safe by default


if __name__ == "__main__":
    if HAS_RUAMEL:
        data = load_ruamel_safe()
        print(f"Loaded: {data}")
    else:
        print("ruamel.yaml not installed")
