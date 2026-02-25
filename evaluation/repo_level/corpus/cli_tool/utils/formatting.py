from __future__ import annotations

from typing import Union


def format_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}PB"


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes, secs = divmod(seconds, 60)
        return f"{int(minutes)}m {int(secs)}s"
    else:
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m"


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return singular
    return plural or f"{singular}s"


def format_table(
    rows: list[list[str]],
    headers: list[str] | None = None,
    padding: int = 2,
) -> str:
    if not rows:
        return ""
    
    all_rows = [headers] + rows if headers else rows
    
    col_widths = [0] * len(all_rows[0])
    for row in all_rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    lines = []
    for i, row in enumerate(all_rows):
        cells = [str(cell).ljust(col_widths[j]) for j, cell in enumerate(row)]
        lines.append((" " * padding).join(cells))
        
        if i == 0 and headers:
            separators = ["-" * w for w in col_widths]
            lines.append((" " * padding).join(separators))
    
    return "\n".join(lines)


def truncate(text: str, max_length: int, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def indent(text: str, spaces: int = 2) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.split("\n"))
