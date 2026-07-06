"""
FP Regression Test: Click framework file arguments.

Similar to argparse - Click CLI tool file arguments should NOT be flagged.

Expected: NO FINDINGS (or LOW confidence if any)
"""
try:
    import click
except ImportError:
    # Mock click for testing without the dependency
    class click:
        @staticmethod
        def command():
            return lambda f: f
        @staticmethod  
        def option(*args, **kwargs):
            return lambda f: f
        @staticmethod
        def argument(*args, **kwargs):
            return lambda f: f


@click.command()
@click.option('--config', '-c', default='config.yaml', help='Config file path')
@click.option('--input-file', '-i', type=click.Path(exists=True), help='Input file')
@click.argument('output', type=click.Path())
def process(config, input_file, output):
    """Process files - a CLI tool."""
    
    # These should NOT be flagged as PATH_INJECTION
    with open(config, 'r') as f:  # Should NOT flag
        config_data = f.read()
    
    if input_file:
        with open(input_file, 'r') as f:  # Should NOT flag
            data = f.read()
    
    with open(output, 'w') as f:  # Should NOT flag
        f.write("processed")


if __name__ == "__main__":
    process()
