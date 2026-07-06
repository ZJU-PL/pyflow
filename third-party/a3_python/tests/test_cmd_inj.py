#!/usr/bin/env python3
"""Test command injection detection on cmd_lab pattern."""
import sys
sys.path.insert(0, '.')
from a3_python.semantics.intraprocedural_taint import IntraproceduralTaintAnalyzer
import dis

# Compile with real structure from cmd_lab
code = '''
def cmd_lab(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            domain = request.POST.get("domain")
            domain = domain.replace("https://www.", "")
            os = request.POST.get("os")
            if os == "win":
                command = "nslookup {}".format(domain)
            else:
                command = "dig {}".format(domain)
            import subprocess
            subprocess.Popen(command, shell=True)
'''
exec(compile(code, '<test>', 'exec'))
func = cmd_lab

# Analyze
analyzer = IntraproceduralTaintAnalyzer(
    func.__code__,
    function_name='cmd_lab',
    file_path='test.py'
)

bugs = analyzer.analyze()
print(f'Bugs found: {len(bugs)}')
for b in bugs:
    print(f'  {b.bug_type} at line {b.line_number}')
    print(f'    Source: {b.source_description}')
    print(f'    Sink: {b.sink_description}')
