
"""Utility functions for formatting plugins for PyFlow Checker."""
import io


def wrap_file_object(fileobj):
    """If the fileobj passed in cannot handle text, use TextIOWrapper
    to handle the conversion.
    """
    if isinstance(fileobj, io.TextIOBase):
        return fileobj
    return io.TextIOWrapper(fileobj)
