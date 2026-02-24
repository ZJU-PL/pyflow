from __future__ import absolute_import

from ..stubcollector import stubgenerator

import subprocess


@stubgenerator
def makeSubprocessStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### subprocess.run ###
    @export
    @attachPtr(subprocess, "run")
    @llfunc
    def subprocess_run(args, stdin=None, input=None, stdout=None, stderr=None, capture_output=False, shell=False, cwd=None, timeout=None, check=False, encoding=None, errors=None, text=None, env=None, universal_newlines=None, **kwargs):
        return allocate(subprocess.CompletedProcess)

    ### subprocess.call ###
    @export
    @attachPtr(subprocess, "call")
    @llfunc
    def subprocess_call(args, stdin=None, stdout=None, stderr=None, shell=False, cwd=None, timeout=None, **kwargs):
        return allocate(int)

    ### subprocess.check_call ###
    @export
    @attachPtr(subprocess, "check_call")
    @llfunc
    def subprocess_check_call(args, stdin=None, stdout=None, stderr=None, shell=False, cwd=None, timeout=None, **kwargs):
        return allocate(int)

    ### subprocess.check_output ###
    @export
    @attachPtr(subprocess, "check_output")
    @llfunc
    def subprocess_check_output(args, stdin=None, stderr=None, shell=False, cwd=None, timeout=None, encoding=None, errors=None, **kwargs):
        return allocate(bytes)

    ### subprocess.Popen ###
    @export
    @attachPtr(subprocess, "Popen")
    @llfunc
    def subprocess_Popen(args, bufsize=-1, executable=None, stdin=None, stdout=None, stderr=None, preexec_fn=None, close_fds=True, shell=False, cwd=None, env=None, universal_newlines=None, startupinfo=None, creationflags=0, restore_signals=True, start_new_session=False, pass_fds=(), encoding=None, errors=None, text=None):
        return allocate(subprocess.Popen)

    ### Popen methods ###
    @attachPtr(subprocess.Popen, "poll")
    @llfunc
    def popen_poll(self):
        return allocate(int)

    @attachPtr(subprocess.Popen, "wait")
    @llfunc
    def popen_wait(self, timeout=None):
        return allocate(int)

    @attachPtr(subprocess.Popen, "communicate")
    @llfunc
    def popen_communicate(self, input=None, timeout=None):
        return allocate(tuple)

    @attachPtr(subprocess.Popen, "send_signal")
    @llfunc
    def popen_send_signal(self, signal):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "terminate")
    @llfunc
    def popen_terminate(self):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "kill")
    @llfunc
    def popen_kill(self):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "stdin")
    @llfunc
    def popen_stdin_get(self):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "stdout")
    @llfunc
    def popen_stdout_get(self):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "stderr")
    @llfunc
    def popen_stderr_get(self):
        return allocate(type(None))

    @attachPtr(subprocess.Popen, "pid")
    @llfunc
    def popen_pid_get(self):
        return allocate(int)

    @attachPtr(subprocess.Popen, "returncode")
    @llfunc
    def popen_returncode_get(self):
        return allocate(int)

    ### CompletedProcess ###
    @attachPtr(subprocess.CompletedProcess, "args")
    @llfunc
    def completedprocess_args_get(self):
        return allocate(list)

    @attachPtr(subprocess.CompletedProcess, "returncode")
    @llfunc
    def completedprocess_returncode_get(self):
        return allocate(int)

    @attachPtr(subprocess.CompletedProcess, "stdout")
    @llfunc
    def completedprocess_stdout_get(self):
        return allocate(bytes)

    @attachPtr(subprocess.CompletedProcess, "stderr")
    @llfunc
    def completedprocess_stderr_get(self):
        return allocate(bytes)

    @attachPtr(subprocess.CompletedProcess, "check_returncode")
    @llfunc
    def completedprocess_check_returncode(self):
        return allocate(type(None))

    ### PIPE, STDOUT, DEVNULL constants ###
    @llfunc
    def subprocess_PIPE_get():
        return allocate(int)

    @llfunc
    def subprocess_STDOUT_get():
        return allocate(int)

    @llfunc
    def subprocess_DEVNULL_get():
        return allocate(int)

    ### list2cmdline ###
    @export
    @attachPtr(subprocess, "list2cmdline")
    @llfunc
    def subprocess_list2cmdline(seq):
        return allocate(str)
