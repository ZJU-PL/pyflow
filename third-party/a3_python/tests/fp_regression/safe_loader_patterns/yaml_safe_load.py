"""
FP Regression Test: Safe YAML loaders.

yaml.safe_load() and equivalent safe loaders should NEVER be flagged
as YAML_INJECTION or CODE_INJECTION - they are explicitly designed
to be safe against arbitrary code execution.

Expected: NO FINDINGS
"""
import yaml


def load_config_safe():
    """Load YAML with safe_load - should NOT flag."""
    
    yaml_content = """
    database:
      host: localhost
      port: 5432
    """
    
    # safe_load is explicitly safe - no !!python/object attacks work
    config = yaml.safe_load(yaml_content)  # Should NEVER flag
    
    return config


def load_multiple_safe():
    """Load multiple YAML documents safely."""
    
    yaml_content = """
    ---
    name: doc1
    ---
    name: doc2
    """
    
    # safe_load_all is also safe
    docs = list(yaml.safe_load_all(yaml_content))  # Should NEVER flag
    
    return docs


def load_from_file_safe(filepath):
    """Load YAML from file with safe_load."""
    
    with open(filepath, 'r') as f:
        # Even with external file, safe_load is safe
        config = yaml.safe_load(f)  # Should NEVER flag YAML_INJECTION
    
    return config


# CONTRAST: These SHOULD be flagged (for testing baseline)
def load_unsafe_for_comparison():
    """UNSAFE: yaml.load without safe loader - SHOULD flag."""
    yaml_content = "test: value"
    
    # This is the vulnerable pattern
    # config = yaml.load(yaml_content, Loader=yaml.FullLoader)  # SHOULD flag
    # config = yaml.load(yaml_content, Loader=yaml.UnsafeLoader)  # SHOULD flag
    pass


if __name__ == "__main__":
    config = load_config_safe()
    print(f"Loaded: {config}")
