"""
File system utilities for PyFlow.

Provides helper functions for file and directory operations including
directory creation, path joining, file I/O, and file hash computation
for change detection.
"""
import os.path
import hashlib


def ensureDirectoryExists(dirname):
    """
    Ensure that a directory exists, creating it if necessary.
    
    Creates the directory and all necessary parent directories if they
    don't already exist. Safe to call multiple times.
    
    Args:
        dirname: Path to the directory to ensure exists
    """
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def join(directory, name, format=None):
    """
    Join directory path with filename, optionally adding a format extension.
    
    Args:
        directory: Directory path
        name: Filename (without extension if format is provided)
        format: Optional file extension/format to append (without the dot)
        
    Returns:
        Full path to the file
        
    Example:
        join("/path/to", "output", "txt") -> "/path/to/output.txt"
    """
    if format is not None:
        name = "%s.%s" % (name, format)
    return os.path.join(directory, name)


def relative(path, root):
    """
    Compute the relative path from root to path.
    
    Args:
        path: Target path (absolute or relative)
        root: Base directory to compute relative path from
        
    Returns:
        Relative path from root to path
    """
    return os.path.relpath(path, root)


def fileInput(directory, name, format=None, binary=False):
    """
    Open a file for reading.
    
    Args:
        directory: Directory containing the file
        name: Filename (without extension if format is provided)
        format: Optional file extension/format
        binary: If True, open in binary mode, otherwise text mode
        
    Returns:
        Open file object ready for reading
    """
    fullname = join(directory, name, format)
    f = open(fullname, "rb" if binary else "r")
    return f


def readData(directory, name, format=None, binary=False):
    """
    Read the entire contents of a file.
    
    Args:
        directory: Directory containing the file
        name: Filename (without extension if format is provided)
        format: Optional file extension/format
        binary: If True, read as binary data, otherwise as text
        
    Returns:
        File contents as string (text mode) or bytes (binary mode)
    """
    f = fileInput(directory, name, format, binary=binary)
    result = f.read()
    f.close()
    return result


def fileOutput(directory, name, format=None, binary=False):
    """
    Open a file for writing, creating the directory if necessary.
    
    The directory will be created if it doesn't exist. The file is opened
    for writing and will overwrite any existing file.
    
    Args:
        directory: Directory to write the file to (created if missing)
        name: Filename (without extension if format is provided)
        format: Optional file extension/format
        binary: If True, open in binary mode, otherwise text mode
        
    Returns:
        Open file object ready for writing
    """
    ensureDirectoryExists(directory)
    fullname = join(directory, name, format)
    f = open(fullname, "wb" if binary else "w")
    return f


def writeData(directory, name, format, data, binary=False):
    """
    Write data to a file, creating the directory if necessary.
    
    Opens the file, writes all data, and closes it. The directory will
    be created if it doesn't exist.
    
    Args:
        directory: Directory to write the file to (created if missing)
        name: Filename (without extension if format is provided)
        format: File extension/format
        data: Data to write (string for text mode, bytes for binary mode)
        binary: If True, write in binary mode, otherwise text mode
    """
    f = fileOutput(directory, name, format, binary=binary)
    f.write(data)
    f.close()


def writeBinaryData(directory, name, format, data):
    """
    Write binary data to a file.
    
    Convenience wrapper around writeData with binary=True.
    
    Args:
        directory: Directory to write the file to (created if missing)
        name: Filename (without extension if format is provided)
        format: File extension/format
        data: Binary data (bytes) to write
    """
    writeData(directory, name, format, data, binary=True)


def dataHash(s):
    """
    Compute SHA-1 hash of data.
    
    Args:
        s: Data to hash (must be bytes for hashlib)
        
    Returns:
        SHA-1 digest (bytes, not hex string)
    """
    h = hashlib.sha1()
    h.update(s)
    return h.digest()
    # return h.hexdigest()


def fileHash(directory, name, format=None, binary=False):
    """
    Compute SHA-1 hash of a file's contents.
    
    Args:
        directory: Directory containing the file
        name: Filename (without extension if format is provided)
        format: Optional file extension/format
        binary: If True, read as binary data, otherwise as text
        
    Returns:
        SHA-1 digest (bytes) of the file contents
    """
    return dataHash(readData(directory, name, format, binary))


def writeFileIfChanged(directory, name, format, data, binary=False):
    """
    Write data to a file only if it differs from the existing file.
    
    Computes the hash of existing file (if it exists) and compares it
    with the hash of the new data. Only writes if they differ, avoiding
    unnecessary file modifications.
    
    Args:
        directory: Directory to write the file to (created if missing)
        name: Filename (without extension if format is provided)
        format: File extension/format
        data: Data to write (string for text mode, bytes for binary mode)
        binary: If True, write in binary mode, otherwise text mode
        
    Returns:
        True if the file was written (either didn't exist or changed),
        False if the file already contained the same data
    """
    if os.path.exists(join(directory, name, format)):
        if fileHash(directory, name, format, binary) == dataHash(data):
            return False

    writeData(directory, name, format, data, binary)
    return True
