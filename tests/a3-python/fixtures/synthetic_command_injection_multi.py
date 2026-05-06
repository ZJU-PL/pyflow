# Synthetic command injection tests - multiple patterns
import os
import subprocess

def cmd_bug_1(user_input):
    """os.system with concatenation - SHOULD FIND BUG"""
    os.system("ls " + user_input)

def cmd_bug_2(user_input):
    """subprocess.run with shell=True - SHOULD FIND BUG"""
    subprocess.run(f"cat {user_input}", shell=True)

def cmd_bug_3(user_input):
    """subprocess.call with shell - SHOULD FIND BUG"""
    subprocess.call("grep pattern " + user_input, shell=True)

def cmd_safe_1(user_input):
    """subprocess.run without shell - SHOULD BE SAFE"""
    subprocess.run(["cat", user_input], shell=False)

def cmd_safe_2(user_input):
    """subprocess.run with list args - SHOULD BE SAFE"""
    subprocess.run(["ls", "-l", user_input])

def cmd_bug_4(user_input):
    """os.popen - SHOULD FIND BUG"""
    result = os.popen("echo " + user_input)
    return result.read()

def cmd_bug_5(filename):
    """eval on user input - SHOULD FIND BUG"""
    code = "print('" + filename + "')"
    eval(code)
