"""Utility functions for formatting plugins for PyFlow Checker."""

import io


def wrap_file_object(fileobj):
    """If the fileobj passed in cannot handle text, use TextIOWrapper
    to handle the conversion.
    """
    mode = getattr(fileobj, "mode", "")
    if isinstance(fileobj, io.TextIOBase):
        return fileobj
    if isinstance(fileobj, io.BytesIO):
        return io.TextIOWrapper(fileobj)
    if mode and "b" not in mode:
        return fileobj
    return io.TextIOWrapper(fileobj)


def issue_sort_key(issue):
    if isinstance(issue, dict):
        values = (
            issue.get("filename", ""),
            issue.get("line_number"),
            issue.get("test_id", ""),
            issue.get("test_name", ""),
            issue.get("issue_text", ""),
        )
    else:
        values = (
            getattr(issue, "fname", ""),
            getattr(issue, "lineno", None),
            getattr(issue, "test_id", ""),
            getattr(issue, "test", ""),
            getattr(issue, "text", ""),
        )
    filename, line, rule, name, message = values
    return str(filename), int(line or -1), str(rule), str(name), str(message)


def issue_report(manager, sev_level, conf_level, *, lines=-1):
    """Assemble shared JSON/YAML data, including baseline candidates."""
    import datetime

    errors = sorted(
        (
            manager.get_errors()
            if hasattr(manager, "get_errors")
            else (
                {"filename": filename, "reason": reason}
                for filename, reason in manager.get_skipped()
            )
        ),
        key=lambda item: (item["filename"], item["reason"]),
    )
    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    collector = []
    for issue in results:
        data = issue.as_dict(max_lines=lines)
        data["more_info"] = (
            issue.cwe.link()
            if issue.cwe.id
            else "https://pyflow.readthedocs.io/en/latest/how-to/security-analysis.html"
        )
        if not isinstance(results, list) and len(results[issue]) > 1:
            data["candidates"] = [
                candidate.as_dict(max_lines=lines) for candidate in results[issue]
            ]
        collector.append(data)
    return {
        "results": sorted(collector, key=issue_sort_key),
        "errors": errors,
        "metrics": manager.metrics.data,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
