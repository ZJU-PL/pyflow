# Synthetic path injection tests
import os

def path_bug_1(user_input):
    """Direct path concatenation - SHOULD FIND BUG"""
    filepath = "/var/data/" + user_input
    with open(filepath, 'r') as f:
        return f.read()

def path_bug_2(user_input):
    """Format string path - SHOULD FIND BUG"""
    filepath = f"/var/data/{user_input}"
    with open(filepath, 'r') as f:
        return f.read()

def path_safe_1(user_input):
    """os.path.basename sanitizer - SHOULD BE SAFE"""
    safe_name = os.path.basename(user_input)
    filepath = f"/var/data/{safe_name}"
    with open(filepath, 'r') as f:
        return f.read()

def path_safe_2(user_input):
    """Constant suffix only - SHOULD BE SAFE"""
    filepath = "/var/data/file.txt"
    with open(filepath, 'r') as f:
        return f.read()

def path_bug_3(user_input):
    """os.remove with user input - SHOULD FIND BUG"""
    filepath = "/tmp/" + user_input
    os.remove(filepath)

def path_bug_4(user_input):
    """Tarfile extraction - SHOULD FIND BUG"""
    import tarfile
    with tarfile.open('archive.tar') as tar:
        tar.extractall(path=user_input)
