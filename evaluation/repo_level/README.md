# Repo-Level Regression Corpus

This directory contains a local, reproducible corpus used to detect analyzer regressions.

## Layout

- `corpus/`: test project snapshots
- `manifest.json`: project metadata

## Projects

| Project | Description |
|---------|-------------|
| `repo_sample` | Original sample with asyncio, dataclasses, star imports |
| `ml_utils` | ML utilities with generics, protocols, ABCs, decorators |
| `web_framework` | Web framework with metaclasses, middleware, context managers |
| `data_pipeline` | Data pipeline with generators, itertools, mixins |
| `cli_tool` | CLI tool with argparse, logging, config management |
