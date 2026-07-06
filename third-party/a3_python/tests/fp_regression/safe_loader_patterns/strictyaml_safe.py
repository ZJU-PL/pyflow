"""
FP Regression Test: strictyaml (always safe).

strictyaml is a YAML library that ONLY supports safe YAML.
It should NEVER be flagged as YAML_INJECTION.

Expected: NO FINDINGS
"""

try:
    import strictyaml
    HAS_STRICTYAML = True
except ImportError:
    HAS_STRICTYAML = False
    # Mock for static analysis
    class strictyaml:
        @staticmethod
        def load(yaml_string, schema=None):
            return {"data": yaml_string}


def load_strictyaml():
    """Load with strictyaml - ALWAYS safe, should NOT flag."""
    
    yaml_content = """
    name: myapp
    port: 8080
    debug: true
    """
    
    # strictyaml is designed to be safe - it doesn't support
    # arbitrary Python object deserialization at all
    data = strictyaml.load(yaml_content)  # Should NEVER flag
    
    return data.data if hasattr(data, 'data') else data


def load_strictyaml_with_schema():
    """Load with strictyaml and schema validation."""
    
    yaml_content = """
    name: myapp
    port: 8080
    """
    
    # With schema, strictyaml is even more restrictive
    # (we're not using a real schema here for simplicity)
    data = strictyaml.load(yaml_content, schema=None)  # Should NEVER flag
    
    return data


if __name__ == "__main__":
    if HAS_STRICTYAML:
        data = load_strictyaml()
        print(f"Loaded: {data}")
    else:
        print("strictyaml not installed")
