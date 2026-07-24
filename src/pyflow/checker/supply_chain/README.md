# PyFlow Supply-Chain Analysis

This package provides local, Python-focused software supply-chain analysis for
the `pyflow supply-chain` CLI. It is intended for experimentation and as an
additional CI signal; it is not yet a replacement for a mature vulnerability
scanner or enterprise supply-chain security platform.

Current capabilities include:

- inventory from common Python manifests, lockfiles, installed metadata,
  wheels, and source distributions;
- CycloneDX 1.7 and SPDX 2.3 SBOM generation;
- offline matching against local OSV data, with VEX qualification;
- license, package-name, distribution-integrity, and installation-script checks;
- bounded archive inspection for traversal, links, collisions, and compression
  bombs;
- policy baselines, SARIF output, in-toto/SLSA provenance checks, and optional
  verification through the Sigstore CLI.

Important limitations:

- vulnerability matching generally requires exact package versions and does
  not perform full dependency resolution;
- reachability currently means conservative source-import evidence, not proof
  that a vulnerable function is callable;
- advisory database acquisition and freshness are managed by the caller;
- provenance policy validation and ecosystem coverage remain narrower than
  established production tools.

## Potential niche

PyFlow may have an interesting niche at the intersection of Python static
analysis and supply-chain security. Unlike a conventional manifest scanner,
PyFlow already contains call-graph, pointer, IFDS/dataflow, and other semantic
analysis infrastructure. Connecting those analyses to dependency and advisory
metadata could support function-level vulnerable-code reachability, malicious
installation-behavior analysis, and more precise exploitability triage. That is
the clearest path for this package to become differentiated rather than another
general-purpose dependency scanner.

## Related work and tools

The following projects provide useful comparison points and are generally more
mature within their respective scopes:

- [pip-audit](https://github.com/pypa/pip-audit) is the PyPA tool for auditing
  Python environments and dependency trees against vulnerability services.
- [OSV-Scanner](https://github.com/google/osv-scanner) scans lockfiles, source
  trees, containers, and SBOMs across multiple ecosystems using OSV data.
- [Syft](https://github.com/anchore/syft) and
  [Grype](https://github.com/anchore/grype) provide broad package inventory,
  SBOM generation, container support, and vulnerability prioritization.
- [Trivy](https://github.com/aquasecurity/trivy) combines dependency and OS
  vulnerability scanning with container, Kubernetes, IaC, secret, license, and
  misconfiguration analysis.
- [GuardDog](https://github.com/DataDog/guarddog) detects potentially malicious
  packages using source-code and package-metadata heuristics, including checks
  for PyPI packages and installation behavior.
- [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan), together with
  cdxgen and its analysis backends, combines SBOM-based vulnerability scanning
  with reachability and risk prioritization across several languages.

PyFlow should complement these tools rather than reproduce their ecosystem and
container coverage. Its strongest prospective contribution is Python-specific
semantic analysis: connecting advisories and package behavior to call graphs,
dataflow, alias information, and precise source-level evidence.

Focused tests live in `tests/checker/supply_chain` and
`tests/cli/test_supply_chain.py`.
