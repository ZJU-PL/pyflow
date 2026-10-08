# PyFlow usage examples

These programs call PyFlow APIs and show how to integrate or extend the tool.
Run them from the repository root after installing PyFlow (`pip install -e .`).

| Example | Purpose | Run |
| --- | --- | --- |
| `ifds_plugin.py` | Write a small IFDS analysis; start with a bundled input | `python examples/ifds_plugin.py` |
| `pass_manager_demo.py` | Define a pass, run it on a loaded program, and read its result | `python examples/pass_manager_demo.py` |

The [IFDS plugin tutorial](../docs/source/how-to/ifds-plugin.rst) explains the
plugin and its regression test.

Put analysis inputs in [`tests/fixtures/`](../tests/fixtures/README.md),
or alongside the test suite that uses them.
