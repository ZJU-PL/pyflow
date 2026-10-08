# Analysis inputs

Python programs for exercising PyFlow's analyses: control flow, typing, objects,
imports, recursion, concurrency, and security patterns.

Run from the repository root after installing PyFlow:

```bash
pyflow callgraph tests/fixtures/analysis_inputs/simple_callgraph.py
pyflow ir tests/fixtures/analysis_inputs/control_flow.py --dump-cfg is_even
pyflow callgraph tests/fixtures/analysis_inputs/mir/callbacks.py --algorithm pycg-mir
pyflow security tests/fixtures/analysis_inputs/class_pollution_example.py
```

Some inputs require optional libraries or contain constructs that an analysis
may only partially support. These files provide inputs rather than expected
results; tests define the assertions for supported behavior.
