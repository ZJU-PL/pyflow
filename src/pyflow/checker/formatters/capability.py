"""Capability finding rendering independent of the capability solver."""

from .sarif import physical_location, sarif_document


def capability_sarif(result) -> dict:
    rules = {}
    sarif_results = []
    level_by_category = {
        "process": "error",
        "code": "error",
        "native": "error",
        "network": "warning",
        "file": "warning",
    }
    for finding in result.findings:
        rules.setdefault(
            finding.capability,
            {
                "id": finding.capability,
                "name": finding.capability.replace(".", "_"),
                "shortDescription": {"text": f"Use of {finding.capability} capability"},
            },
        )
        loc = finding.location
        sarif_results.append(
            {
                "ruleId": finding.capability,
                "level": level_by_category.get(finding.category, "note"),
                "message": {"text": finding.reason},
                "locations": [
                    physical_location(
                        loc.filename, line=max(loc.line, 1), column=max(loc.column, 0)
                    )
                ],
                "properties": {
                    "reportKind": finding.report_kind.value,
                    "accessPath": finding.access_path,
                    "category": finding.category,
                    "trace": list(finding.trace),
                    "escapeKind": finding.escape_kind,
                    "boundary": finding.boundary,
                },
            }
        )
    return sarif_document(
        "PyFlow Capability Analysis",
        sarif_results,
        rules=rules.values(),
        run_properties={
            "analysisStatus": result.status,
            "diagnostics": [d.to_dict() for d in result.diagnostics],
        },
        schema="https://json.schemastore.org/sarif-2.1.0.json",
    )
