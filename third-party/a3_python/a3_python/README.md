# A3: Advanced Automated Analysis for Python

This README documents the `a3_python` subsystem as it exists in this
repository.

The implementation originated from the standalone
`thehalleyyoung/a3-python` project, but development here continues against the
current PyFlow codebase rather than a generated-from-scratch analyzer.

**Find real bugs in Python codebases — automatically.**

A3 combines **non-LLM static analysis** with **agentic LLM triage** for 99%+ accuracy:

1. **Static analysis first**: Uses bytecode analysis, barrier-certificate proofs, and Z3-backed symbolic execution to automatically prove 99% of candidates as false positives
2. **Agentic LLM triage second**: An LLM agent explores the codebase — reading files, searching for guard patterns, checking callers, inspecting tests — then classifies the remaining 1% as TP or FP

No overwhelming noise. No alert fatigue. Just real bugs that matter.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/a3-python.svg)](https://pypi.org/project/a3-python/)

## Quick Start

### Install

```bash
pip install a3-python
```

Requires **Python ≥ 3.11**. The only core dependency is `z3-solver` (installed automatically).

For CI features (GitHub Actions workflows, LLM triage, SARIF output):

```bash
pip install a3-python[ci]
```

### Scan a project

```bash
a3 scan . --output-sarif results.sarif
```

That's it. A3 runs a 7-step pipeline — call graph construction, crash summary computation, guard detection, barrier-certificate proofs, DSE confirmation — and reports the surviving true-positive candidates.

### Scan + agentic triage (end-to-end, single command)

```bash
a3 scan . --triage
```

That's it — one command. A3 scans, writes SARIF, then auto-detects your API key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GITHUB_TOKEN`) and launches an **agentic triage** where the LLM explores the codebase using tools (reading files, searching for guards, checking callers and tests) before classifying each finding. Only confirmed true positives survive.

You can also specify the provider explicitly:

```bash
a3 scan . --triage openai --output-sarif results.sarif
a3 scan . --triage github                # uses GITHUB_TOKEN, free in CI
a3 scan . --triage anthropic              # uses ANTHROPIC_API_KEY
```

#### Using GitHub Models locally (free, no API key needed)

If you have the [GitHub CLI](https://cli.github.com/) installed and authenticated (`gh auth login`), you can use GitHub Models for triage locally — no API key signup required:

```bash
export GITHUB_TOKEN=$(gh auth token) && a3 scan . --triage github --verbose
```

This exports your existing GitHub CLI token and uses it to access GitHub Models for agentic triage. In CI (GitHub Actions), `GITHUB_TOKEN` is already available automatically.

Or run scan and triage as separate steps:

```bash
a3 scan . --output-sarif results.sarif
a3 triage --sarif results.sarif --provider openai --agentic --verbose
```

### Scan with all features enabled

```bash
# Symbolic execution portfolio (kitchensink) is enabled by default
a3 scan /path/to/project \
  --interprocedural \
  --dse-verify \
  --deduplicate \
  --min-confidence 0.3

# To disable portfolio analysis (not recommended):
a3 scan /path/to/project --no-kitchensink
```

### Output SARIF for GitHub Code Scanning

```bash
a3 scan /path/to/project --output-sarif results.sarif
```

Upload the SARIF file to GitHub's [Code Scanning](https://docs.github.com/en/code-security/code-scanning) dashboard, or use the built-in CI integration (see below).

---

## Continuous CI with Agentic Triage

A3 ships with GitHub Actions workflows that **continuously scan every push and every PR** using a **two-phase approach**:

1. **Non-LLM static analysis** scans the repo and automatically proves 99% as false positives
2. **Agentic LLM triage** investigates the remaining 1% — the LLM reads source files, searches for guard patterns, checks callers and tests, then classifies each finding — zero API keys needed

Every GitHub Actions runner already has a `GITHUB_TOKEN`, which gives access to GitHub Models. That's all the agentic triage needs.

### Add to any repo in 60 seconds

```bash
cd your-repo/
pip install a3-python[ci]
a3 init . --copilot
git add .github/ .a3.yml .a3-baseline.json
git commit -m "ci: add a3 static analysis"
git push
```

That's it. Every push to `main`/`master` and every PR that touches Python files will now be scanned, triaged by an agentic LLM, and checked against the baseline. Results appear in GitHub's **Code Scanning** dashboard (Security → Code scanning alerts).

### What `a3 init --copilot` creates

| File | What it does |
|------|-------------|
| `.github/workflows/a3-pr-scan.yml` | **On every push & PR:** scans the repo → agentic LLM investigates each finding (reads files, searches patterns, checks callers) → blocks if new bugs found → uploads SARIF |
| `.github/workflows/a3-scheduled-scan.yml` | **Weekly (Monday 6 AM UTC):** full-repo scan → agentic triage → auto-files GitHub Issues for new TPs → updates baseline |
| `.a3.yml` | Analysis configuration (what to scan, confidence thresholds, etc.) |
| `.a3-baseline.json` | Known-findings baseline for the ratchet (starts empty) |

### How it works end-to-end

```
push to main/master — or — PR opened (touches .py files)
  │
  ├─ 1. Non-LLM static analysis scans the repo
  │     • Bytecode analysis + Z3 symbolic execution
  │     • Automatically proves 99% as false positives
  │     • Outputs SARIF with remaining 1% of findings
  │
  ├─ 2. Agentic LLM triage (multi-turn tool-use)
  │     • For each surviving finding, an LLM agent:
  │       - Reads the flagged function's source code
  │       - Searches for guard checks, callers, tests
  │       - Follows imports and explores related files
  │       - Calls 'classify' with verdict + rationale
  │     • Uses GITHUB_TOKEN → GitHub Models (zero config)
  │
  ├─ 3. Baseline ratchet check
  │     new bugs not in baseline → ❌ CI fails
  │     all bugs already known   → ✅ CI passes
  │
  └─ 4. SARIF uploaded to GitHub Code Scanning dashboard
        findings appear under Security → Code scanning alerts
```

### Example: What the workflow file looks like

When you run `a3 init . --copilot`, it creates `.github/workflows/a3-pr-scan.yml`. Here's the key steps:

```yaml
# .github/workflows/a3-pr-scan.yml
# Triggers on: push to main/master, all PRs touching .py files

- name: Get changed files
  id: changed
  run: |
    git diff --name-only --diff-filter=ACMR "$BASE"...HEAD -- '*.py' > changed_files.txt

- name: Run a3
  run: |
    a3 scan . \
      --output-sarif a3-results.sarif

- name: Agentic triage                        # ← the magic step
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # ← already exists, no setup
  run: |
    a3 triage \
      --sarif a3-results.sarif \
      --output-sarif a3-triaged.sarif \
      --repo-root . \
      --provider github \
      --model gpt-5.4 \
      --agentic \
      --verbose
    mv a3-triaged.sarif a3-results.sarif

- name: Check baseline
  run: a3 baseline diff --sarif a3-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: a3-results.sarif
```

The agentic triage step gives the LLM tools to explore the repo — `read_file`, `search_codebase`, `get_function_source`, `get_imports`, `list_directory` — so it can check callers, find tests, verify guards, and understand context before classifying each finding.

### The ratchet: incremental adoption for large codebases

The baseline file records all *accepted* findings. On each PR:

- **New findings not in baseline → CI fails.** The author must fix the bug or explicitly accept it.
- **Findings that disappear → auto-pruned.** The codebase is getting healthier.
- **Pre-existing issues → ignored.** You're never blocked on legacy debt.

```bash
# Check for new findings (exits 1 if any are new)
a3 baseline diff --sarif results.sarif

# Accept current findings into baseline
a3 baseline accept --sarif results.sarif
```

### Two Usage Patterns

#### Scenario A: Whole-Repo Scan

Scan every Python file in one pass. Best for first-time adoption, weekly audits, or establishing a baseline.

```bash
# Scan the entire repository
a3 scan . --interprocedural --dse-verify --output-sarif results.sarif

# Agentic triage (optional — filters remaining false positives)
a3 triage --sarif results.sarif --provider github --agentic \
  --output-sarif triaged.sarif

# Lock current findings as the baseline (ratchet start)
a3 baseline accept --sarif triaged.sarif
git add .a3-baseline.json && git commit -m "ci: establish a3 baseline" && git push
```

The scheduled workflow (`a3-scheduled-scan.yml`) repeats this automatically every week.

#### Scenario B: Incremental — Auto-Invoke on Every Python File Change

After `a3 init . --copilot`, **no manual step is needed**. The generated `a3-pr-scan.yml` triggers whenever a `.py` file is added or modified:

```yaml
on:
  push:
    branches: [main]
    paths: ["**.py"]          # triggers ONLY when .py files change
  pull_request:
    branches: [main]
    paths: ["**.py"]
```

**Example — adding a new file:**

```bash
cat > src/payments.py << 'EOF'
def charge(amount, discount):
    return amount / discount   # DIV_ZERO: discount could be 0

def refund(amount, count):
    if count > 0:
        return amount / count  # SAFE: guarded by count > 0
    return 0.0
EOF

git add src/payments.py
git commit -m "feat: add payment processing"
git push   # <-- CI auto-triggers, scans only src/payments.py
```

What happens automatically:

1. Push triggers `a3-pr-scan.yml` (path filter matches `**.py`)
2. Workflow detects changed files via `git diff --name-only`
3. a3 scans only `src/payments.py` — finds DIV_ZERO in `charge()`, proves `refund()` safe
4. Baseline diff: new bug not in baseline → **CI fails** until the bug is fixed or accepted

Non-Python changes (docs, configs, images) do not trigger the workflow at all.

---

### Using a different LLM provider (optional)

If you prefer Claude or GPT-5 via your own API key instead of GitHub Models:

```bash
# Anthropic (Claude) — agentic by default
export ANTHROPIC_API_KEY=sk-...
a3 triage --sarif results.sarif --output-sarif triaged.sarif --agentic

# OpenAI (GPT-5)
a3 triage --sarif results.sarif --provider openai --model gpt-5 --agentic

# GitHub Models (via GITHUB_TOKEN — free in CI)
a3 triage --sarif results.sarif --provider github --agentic
```

For third-party providers in GitHub Actions, add the API key as a [repository secret](https://docs.github.com/en/actions/security-guides/encrypted-secrets):

```yaml
- name: LLM triage (Anthropic)
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: a3 triage --sarif a3-results.sarif --output-sarif a3-triaged.sarif --agentic
```

---

## Configuration

Create a `.a3.yml` in your repo root (or use `a3 init` to generate one):

```yaml
analysis:
  interprocedural: true
  # kitchensink: true by default (symbolic execution portfolio)
  dse-verify: true
  min-confidence: 0.3
  deduplicate: true

ci:
  fail-on-new-bugs: true
  baseline-file: .a3-baseline.json
  llm-triage: true             # enabled by default with --copilot
  llm-provider: github         # uses GITHUB_TOKEN — no extra API keys
  llm-model: gpt-5
  sarif-upload: true

scan:
  exclude:
    - "tests/**"
    - "docs/**"
    - "**/test_*.py"
```

When a config file is present, `a3 scan` reads it automatically — no flags needed.

---

## CLI Reference

### `a3 scan`

Run static analysis on a file or project.

```
a3 scan <target> [options]
a3 <target> [options]           # legacy syntax, same behavior
```

**Analysis flags:**

| Flag | Description |
|------|-------------|
| `--interprocedural` | Cross-function analysis with call graph and summaries |
| `--no-kitchensink` | Disable symbolic execution portfolio (enabled by default) |
| `--dse-verify` | Verify bugs with Z3-backed symbolic execution |
| `--deduplicate` | Deduplicate findings by type + location |
| `--min-confidence N` | Filter by confidence score (0.0–1.0, default: 0.7) |
| `--no-intent-filter` | Report all bugs regardless of intent classification |
| `--functions` | Treat each function as a tainted entry point (security mode) |
| `--all-functions` | Analyze every function as an entry point |
| `--context-depth N` | k-CFA context sensitivity (0, 1, 2, …) |
| `--check-termination` | Detect non-terminating loops |
| `--synthesize-invariants` | Generate inductive loop invariants |

**Output flags:**

| Flag | Description |
|------|-------------|
| `--output-sarif PATH` | Write SARIF 2.1.0 JSON |
| `--triage [PROVIDER]` | Run agentic triage after scan (auto-detects API key, or specify: `openai`, `anthropic`, `github`) |
| `--triage-model MODEL` | LLM model for integrated triage (default: provider-appropriate) |
| `--save-results PATH` | Write results as JSON (default: `results/<name>_results.json`) |
| `--verbose` | Detailed step-by-step output |
| `--config PATH` | Path to `.a3.yml` |

**Exit codes:** `0` = no bugs, `1` = bugs found, `2` = unknown, `3` = error.

### `a3 init`

Bootstrap a repository with CI workflows and config.

```
a3 init [repo_path]             # default: current directory
a3 init . --copilot             # enable Copilot triage (recommended)
a3 init . --llm-triage          # enable triage with Anthropic/OpenAI
a3 init . --overwrite           # replace existing files
```

### `a3 triage`

Classify findings via agentic LLM investigation.

```
a3 triage --sarif results.sarif --provider github --agentic     # GitHub Models (recommended)
a3 triage --sarif results.sarif --output-sarif triaged.sarif --agentic  # Anthropic (default provider)
a3 triage --sarif results.sarif --provider openai --model gpt-5 --agentic
a3 triage --sarif results.sarif --verbose --agentic
```

The `--agentic` flag enables multi-turn tool-use: the LLM can read files, search for patterns, inspect callers, check tests, and explore the repo before classifying each finding. Without `--agentic`, a simpler one-shot prompt is used.

Providers: `github` (uses `GITHUB_TOKEN`), `anthropic` (uses `ANTHROPIC_API_KEY`), `openai` (uses `OPENAI_API_KEY`). Pass `--api-key` to override.

### `a3 baseline`

Manage the findings baseline (ratchet).

```
a3 baseline diff --sarif results.sarif        # check for new bugs
a3 baseline accept --sarif results.sarif      # update baseline
a3 baseline diff --sarif results.sarif --auto-issue  # file GitHub issues
```

---

## Detected Bug Types

### Correctness (20 types)

`DIV_ZERO` · `NULL_PTR` · `INDEX_OOB` · `KEY_ERROR` · `TYPE_ERROR` · `ASSERT_FAIL` · `UNBOUND_VAR` · `INTEGER_OVERFLOW` · `NON_TERMINATION` · `MEMORY_LEAK` · `USE_AFTER_FREE` · `DOUBLE_FREE` · `DATA_RACE` · `DEADLOCK` · `TIMING_CHANNEL` · `INFO_LEAK` · `BOUNDS` · `RUNTIME_ERROR` · `TYPE_CONFUSION` · `OVERFLOW`

### Security (47 types)

**Injection:** `SQL_INJECTION` · `COMMAND_INJECTION` · `CODE_INJECTION` · `PATH_INJECTION` · `LDAP_INJECTION` · `XPATH_INJECTION` · `NOSQL_INJECTION` · `REGEX_INJECTION` · `HEADER_INJECTION` · `COOKIE_INJECTION`

**Web:** `REFLECTED_XSS` · `SSRF` · `PARTIAL_SSRF` · `URL_REDIRECT` · `CSRF_PROTECTION_DISABLED` · `FLASK_DEBUG` · `INSECURE_COOKIE` · `JINJA2_AUTOESCAPE_FALSE`

**Crypto:** `WEAK_CRYPTO` · `WEAK_CRYPTO_KEY` · `BROKEN_CRYPTO_ALGORITHM` · `INSECURE_PROTOCOL`

**Deserialization:** `UNSAFE_DESERIALIZATION` · `XXE` · `XML_BOMB`

**Secrets:** `CLEARTEXT_LOGGING` · `CLEARTEXT_STORAGE` · `HARDCODED_CREDENTIALS`

**Files/Network:** `TAR_SLIP` · `INSECURE_TEMPORARY_FILE` · `WEAK_FILE_PERMISSIONS` · `BIND_TO_ALL_INTERFACES` · `MISSING_HOST_KEY_VALIDATION` · `CERT_VALIDATION_DISABLED`

**Regex DoS:** `REDOS` · `POLYNOMIAL_REDOS` · `BAD_TAG_FILTER` · `INCOMPLETE_HOSTNAME_REGEXP`

---

## How It Works

### Phase 1: Non-LLM Static Analysis (filters 99% of bugs)

A3 runs a **7-step symbolic execution pipeline** using formal methods — no AI, no heuristics:

1. **Call Graph** — Builds a whole-program call graph from all `.py` files
2. **Crash Summaries** — Disassembles bytecode to find divisions, None-dereferences, out-of-bounds accesses, taint flows, and 67 other bug patterns
3. **Symbolic Model Construction** — Builds Z3 symbolic representations of Python code objects
4. **Guard Detection** — Identifies bugs already protected by `if`, `try/except`, `assert`, `isinstance` checks using symbolic constraints
5. **Z3 Symbolic Execution** — Uses Z3 SMT solver to prove whether bugs are reachable by constructing satisfying assignments
6. **Staged Portfolio** — Runs multiple proof strategies in parallel (barrier certificates, inductive invariants, k-induction)
7. **Classification** — Separates production code from test code

Each bug receives one of three verdicts:

| Verdict | Meaning |
|---------|---------|
| **FP (proven)** | Barrier certificate or DSE proves the bug is unreachable — **99% of findings** |
| **TP candidate** | No proof found; send to LLM for verification — **~1% of findings** |
| **DSE-confirmed TP** | Z3 found a satisfying input that triggers the crash — **Even more likely bug** |

### Phase 2: Agentic LLM Triage (investigates the remaining 1%)

For findings that survive static analysis, A3 launches an **agentic investigation** — a multi-turn conversation where the LLM has access to tools:

| Tool | What it does |
|------|-------------|
| `read_file` | Read any source file (with optional line range) |
| `search_codebase` | Grep for regex patterns across the project |
| `get_function_source` | Look up any function by name |
| `get_imports` | See what a file imports |
| `list_directory` | Explore project structure |
| `classify` | Submit final TP/FP verdict with confidence + rationale |

The agent typically makes 2–6 tool calls per finding — reading callers, checking for guard patterns, looking at tests, following imports — then calls `classify` with its verdict.

This is **not** a one-shot prompt. The LLM decides what to investigate, gathers evidence iteratively, and only classifies when it has enough context. This produces significantly more accurate results than a single-pass LLM call.

---

## Examples

### Quick Demo: Detecting Real Bugs

```python
# examples.py

def authenticate_user(username, user_database):
    """Look up user credentials from database."""
    user_record = user_database.get(username)
    return user_record['password_hash']  # NULL_PTR: user_record could be None

def calculate_completion_rate(completed, total):
    """Calculate completion percentage."""
    return (completed / total) * 100  # DIV_ZERO: total could be 0

def get_database_host(config):
    """Extract database host from config."""
    return config.database.host  # NULL_PTR: config or database could be None

def get_latest_transaction(transactions):
    """Get the most recent transaction."""
    sorted_txns = sorted(transactions, key=lambda t: t.date, reverse=True)
    return sorted_txns[0].amount  # BOUNDS: sorted_txns could be empty

def extract_email_from_csv(csv_line):
    """Parse email from third column of CSV."""
    fields = csv_line.split(',')
    return fields[2].strip()  # BOUNDS: might not have 3 columns

def calculate_roi(profit, cost):
    """Calculate return on investment."""
    return (profit / cost) * 100  # DIV_ZERO: cost could be 0

def get_product_total_price(inventory, product_id):
    """Calculate total price including tax."""
    product = inventory.lookup(product_id)
    return product.base_price * (1 + product.tax_rate)  # NULL_PTR: product could be None
```

Run a3:

```bash
$ a3 scan examples.py --interprocedural

============================================================
INTERPROCEDURAL ANALYSIS RESULTS
============================================================
Total bugs found: 14

BOUNDS (3)
  - examples.get_first_user_email
    examples.py:41
    Confidence: 0.19
  - examples.get_latest_transaction
    examples.py:52
    Confidence: 0.19
  - examples.extract_email_from_csv
    examples.py:76
    Confidence: 0.19

DIV_ZERO (3)
  - examples.calculate_completion_rate
    examples.py:19
    Confidence: 0.21
  - examples.calculate_average_score
    examples.py:64
    Confidence: 0.21
  - examples.calculate_roi
    examples.py:87
    Confidence: 0.21

NULL_PTR (7)
  - examples.get_from_cache
    examples.py:110
    Confidence: 0.19
  - examples.get_database_host
    examples.py:31
    Confidence: 0.19
  - examples.authenticate_user
    examples.py:13
    Confidence: 0.19
  - examples.get_product_total_price
    examples.py:98
    Confidence: 0.19
  - examples.calculate_average_score
    examples.py:64
    Confidence: 0.19
  ... and 2 more

VALUE_ERROR (1)
  - examples.get_first_user_email
    examples.py:38
    Confidence: 0.84
```

### Guard Detection: Safe vs Unsafe Code

A3 automatically recognizes when bugs are properly guarded:

```python
# examples_safe.py

def authenticate_user(username, user_database):
    """SAFE: Checks if user exists."""
    user_record = user_database.get(username)
    if user_record is not None:
        return user_record['password_hash']
    return None

def calculate_completion_rate(completed, total):
    """SAFE: Checks for zero before division."""
    if total != 0:
        return (completed / total) * 100
    return 0.0

def get_database_host(config):
    """SAFE: Validates nested attributes."""
    if config is not None and config.database is not None:
        return config.database.host
    return "localhost"

def get_latest_transaction(transactions):
    """SAFE: Checks if list is empty."""
    sorted_txns = sorted(transactions, key=lambda t: t.date, reverse=True)
    if len(sorted_txns) > 0:
        return sorted_txns[0].amount
    return 0.0

def extract_email_from_csv(csv_line):
    """SAFE: Validates column count with length guard."""
    fields = csv_line.split(',')
    if len(fields) >= 3:
        return fields[2].strip()  # SAFE: len(fields) >= 3 guards fields[2]
    return None
```

```bash
$ a3 scan examples_safe.py --interprocedural

============================================================
INTERPROCEDURAL ANALYSIS RESULTS
============================================================
Total bugs found: 0
```

**All guards successfully detected by Z3 symbolic execution!**

The key improvements:
- ✅ **BOUNDS bugs: 0** (down from 3) - Length guards like `len(fields) >= 3` now correctly protect `fields[2]`
- ✅ **NULL_PTR bugs: 0** (down from 7) - None-checks and nonnull guards detected
- ✅ **DIV_ZERO bugs: 0** (down from 3) - Zero-checks detected

For production use with legacy codebases, enable LLM triage to filter remaining false positives in unguarded code:

```bash
a3 scan examples_safe.py --interprocedural --output-sarif results.sarif
a3 triage --sarif results.sarif --provider github --output-sarif filtered.sarif --agentic
```

With agentic triage, the LLM explores the codebase to verify each finding, achieving 99%+ accuracy.


### Finding Real Bugs in a Large Project

```bash
# Full symbolic execution pipeline (kitchensink enabled by default)
a3 scan . --interprocedural --dse-verify --output-sarif results.sarif

# Agentic triage for remaining 1% after symbolic verification
a3 triage --sarif results.sarif --output-sarif triaged.sarif --provider github --agentic --verbose

# Baseline ratchet check
a3 baseline diff --sarif triaged.sarif --auto-issue
```

---

## Architecture

```
a3_python/
├── cli.py         # CLI with subcommands (scan, init, triage, baseline)
├── analyzer.py    # Core analysis engine
├── frontend/      # Python loading, bytecode compilation
├── cfg/           # Control-flow graph + call graph construction
├── semantics/     # Symbolic bytecode execution, crash summaries
├── z3model/       # Z3 value/heap modeling
├── unsafe/        # Bug type predicates (67 types)
├── contracts/     # External call modeling, taint sources/sinks
├── dse/           # Concolic execution (Z3-backed)
├── barriers/      # Barrier certificate synthesis (10 patterns)
└── ci/            # CI integration
    ├── sarif.py           # SARIF 2.1.0 serializer
    ├── baseline.py        # Ratchet / baseline management
    ├── triage.py          # One-shot LLM classification
    ├── agentic_triage.py  # Multi-turn agentic triage with tool-use
    ├── config.py          # .a3.yml loader
    ├── init_cmd.py        # `a3 init` bootstrapper
    └── templates/         # GitHub Actions workflow YAMLs
```

---

## Development

```bash
git clone https://github.com/thehalleyyoung/a3-python.git
cd a3-python
pip install -e ".[dev,ci]"
pytest
pytest --cov=a3_python
```

## License

See [LICENSE](LICENSE) file.
