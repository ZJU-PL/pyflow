"""Run the CLI with ``python -m pyflow.cli``."""

from .main import entrypoint

if __name__ == "__main__":
    raise SystemExit(entrypoint())
