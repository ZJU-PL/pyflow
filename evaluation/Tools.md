# Tools for Python Code Analysis



## Static Analysis Frameworks

- https://github.com/lkgv/PythonStAn
  + Dataflow Analysis: Liveness analysis, reaching definition analysis, and def-use chains
  + Pointer Analysis: k-CFA based pointer analysis with configurable context sensitivity
  + Control Flow Analysis: CFG generation, interprocedural control flow graphs (ICFG)
  + Abstract Interpretation: AI-based analysis with configurable abstract domains
  + Scope Analysis: Module and function scope management
- https://github.com/SMAT-Lab/Scalpel: Basic IR construction


## Type Checking

- mypy: https://github.com/python/mypy
- pyre-check: https://github.com/facebook/pyre-check Developed by Meta (Facebook), designed for performance in large codebases. It includes a security-focused sub-tool called Pysa (?)
- Pyright: Created by Microsoft (powers VS Code’s Pylance). 

## Bug Finders

- Bandit: The go-to for finding common security flaws (e.g., use of eval(), weak crypto, or insecure permissions).
- Semgrep: A powerful, polyglot engine that uses pattern matching
- Snyk Code: An AI-powered commercial tool that integrates deeply into CI/CD to find vulnerabilities and suggest fixes.
- SonarQube/SonarCloud: Provides static code analysis for bugs, vulnerabilities, and code smells in Python (via SonarPython plugin).


## Linters

- Ruff: https://github.com/astral-sh/ruff. The current industry standard. Written in Rust, it is 10–100x faster than traditional tools. It replaces Flake8, isort, pydocstyle, and many Pylint rules in a single binary.
- Pylint: https://github.com/pylint-dev/pylint. Extremely thorough and highly configurable.
- Flake8: A classic "wrapper" that combines Pyflakes (error checking), pycodestyle (PEP 8 style), and McCabe (complexity).