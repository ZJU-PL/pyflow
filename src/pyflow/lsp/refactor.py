"""Validate a proposed rename against syntax and lexical binding identity."""

import warnings
from .workspace import _cached_uri_to_path, lsp_character_to_offset, uri_to_path


class _LineOffsets:
    """O(1) line/character to absolute offset conversion for one document."""

    __slots__ = ("text", "starts")

    def __init__(self, text: str) -> None:
        self.text = text
        starts = [0]
        index = text.find("\n")
        while index >= 0:
            starts.append(index + 1)
            index = text.find("\n", index + 1)
        self.starts = starts

    def offset(self, line: int, character: int) -> int:
        if line < 0:
            raise ValueError("source position cannot be negative")
        if line >= len(self.starts):
            return len(self.text)
        start = self.starts[line]
        end = self.starts[line + 1] if line + 1 < len(self.starts) else len(self.text)
        return start + lsp_character_to_offset(self.text[start:end], character)


def _line_offsets(sources):
    return {path: _LineOffsets(text) for path, text in sources.items()}


def validate_rename(index, symbol, ranges, new_name):
    if new_name == symbol.name:
        return
    identities = {item.symbol_id for item in index._resolver.property_group(symbol)}
    for _location, _kind, bindings in index._scopes:
        bindings = dict(bindings)
        if any(identity in identities for identity in bindings.values()):
            existing = bindings.get(new_name)
            if existing is not None and existing not in identities:
                raise ValueError(f"Rename conflicts with existing binding '{new_name}'")
    owner = index._resolver.symbols.get(symbol.container_name)
    if (
        owner is not None
        and owner.kind == 5
        or index._resolver.dynamic_namespace(symbol.container_name)
    ):
        existing = index._resolver.member(symbol.container_name, new_name)
        if existing is not None and existing.symbol_id not in identities:
            raise ValueError(f"Rename conflicts with member '{new_name}'")
    original_offsets = _line_offsets(index.source_files)
    edits = {}
    for location in ranges:
        path = uri_to_path(location.uri)
        offsets = original_offsets.get(path)
        if offsets is None:
            raise ValueError("Cannot rename a definition outside the indexed workspace")
        start = offsets.offset(location.start_line, location.start_character)
        end = offsets.offset(location.end_line, location.end_character)
        edits.setdefault(path, []).append((start, end, index.replacement_text(location, new_name)))
    updated = dict(index.source_files)
    for path, changes in edits.items():
        changes.sort()
        text = updated[path]
        for start, end, replacement in reversed(changes):
            text = text[:start] + replacement + text[end:]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            try:
                compile(updated[path], path, "exec", dont_inherit=True)
            except (SyntaxError, ValueError):
                pass
            else:
                try:
                    compile(text, path, "exec", dont_inherit=True)
                except (SyntaxError, ValueError) as error:
                    raise ValueError(f"Rename would produce invalid Python: {error}") from error
        updated[path] = text
    candidate = index.with_source_files(updated)
    updated_offsets = _line_offsets(updated)

    def offset(location, sources):
        table = updated_offsets if sources is updated else original_offsets
        return table[_cached_uri_to_path(location.uri)].offset(
            location.start_line, location.start_character
        )

    def translate(path, position):
        delta = 0
        for start, end, replacement in edits.get(path, ()):
            if position < start:
                break
            if position < end:
                return start + delta
            delta += len(replacement) - (end - start)
        return position + delta

    positions = {
        (
            item.selection_range.uri,
            offset(item.selection_range, updated),
            item.symbol_id.kind,
        ): item.symbol_id
        for item in candidate._symbols_by_id.values()
        if uri_to_path(item.selection_range.uri) in updated
        and item.symbol_id.kind.value != "module"
    }
    mapped = {}
    for item in index._symbols_by_id.values():
        if (
            item.symbol_id.kind.value == "module"
            or uri_to_path(item.selection_range.uri) not in index.source_files
        ):
            continue
        path = uri_to_path(item.selection_range.uri)
        position = translate(path, offset(item.selection_range, index.source_files))
        identity = positions.get((item.selection_range.uri, position, item.symbol_id.kind))
        if identity is None:
            raise ValueError(f"Rename would merge or shadow binding '{item.name}'")
        mapped[item.symbol_id] = identity
    for uri, module in index._module_symbols.items():
        if uri in candidate._module_symbols:
            mapped[module.symbol_id] = candidate._module_symbols[uri].symbol_id
    references = {}
    for reference in candidate.references:
        key = reference.location.uri, offset(reference.location, updated)
        references.setdefault(key, set()).add(reference.symbol_id)
    renamed = {mapped.get(identity, identity) for identity in identities}
    for reference in index.references:
        path = uri_to_path(reference.location.uri)
        position = translate(path, offset(reference.location, index.source_files))
        if reference.string_literal and reference.symbol_id in identities:
            position += 1  # replacement_text emits a quoted identifier
        actual = references.get((reference.location.uri, position), set())
        if reference.symbol_id is not None:
            expected = mapped.get(reference.symbol_id, reference.symbol_id)
            if expected not in actual:
                raise ValueError(
                    f"Rename would change resolution of '{reference.name}' (shadowing or capture)"
                )
        elif actual & renamed:
            raise ValueError(f"Rename would capture unresolved reference '{reference.name}'")
