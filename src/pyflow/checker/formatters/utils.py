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
