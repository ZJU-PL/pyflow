"""Buggy version of cookiecutter hooks.py (bug #4).

The bug: run_script() returns proc.wait() exit code without checking
for non-zero status or raising an exception.  Callers must manually
check the return value, which is error-prone.

Key pattern:
  proc = subprocess.Popen(...)
  return proc.wait()   # ← unchecked exit code
"""

import os
import sys
import logging
import subprocess
import tempfile


EXIT_SUCCESS = 0

_HOOKS = [
    'pre_gen_project',
    'post_gen_project',
]


def find_hooks():
    hooks_dir = 'hooks'
    hooks = {}
    if os.path.isdir(hooks_dir):
        for hook_file in os.listdir(hooks_dir):
            basename = os.path.splitext(hook_file)[0]
            if basename in _HOOKS:
                hooks[basename] = os.path.join(hooks_dir, hook_file)
    return hooks


def run_script(script_path, cwd='.'):
    """Execute a script and return exit code.

    BUG: Returns exit code without checking for non-zero.
    """
    run_thru_shell = sys.platform.startswith('win')
    proc = subprocess.Popen(
        script_path,
        shell=run_thru_shell,
        cwd=cwd
    )
    return proc.wait()


def run_script_with_context(script_path, cwd, context):
    """Execute a script after rendering it with context."""
    with open(script_path, 'r') as f:
        contents = f.read()

    with tempfile.NamedTemporaryFile(
        delete=False,
        mode='w',
        suffix=os.path.splitext(script_path)[1],
    ) as temp:
        temp.write(contents)

    return run_script(temp.name, cwd)


def run_hook(hook_name, project_dir, context):
    """Run a hook if it exists."""
    script = find_hooks().get(hook_name)
    if script is None:
        logging.debug('No hooks found')
        return EXIT_SUCCESS
    return run_script_with_context(script, project_dir, context)
