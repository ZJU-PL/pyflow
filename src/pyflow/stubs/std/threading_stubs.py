from __future__ import absolute_import

from ..stubcollector import stubgenerator

import threading


@stubgenerator
def makeThreadingStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### Thread ###
    @export
    @attachPtr(threading, "Thread")
    @llfunc
    def threading_Thread(group=None, target=None, name=None, args=(), kwargs=None, daemon=None):
        return allocate(threading.Thread)

    @attachPtr(threading.Thread, "start")
    @llfunc
    def thread_start(self):
        return allocate(type(None))

    @attachPtr(threading.Thread, "run")
    @llfunc
    def thread_run(self):
        return allocate(type(None))

    @attachPtr(threading.Thread, "join")
    @llfunc
    def thread_join(self, timeout=None):
        return allocate(type(None))

    @attachPtr(threading.Thread, "is_alive")
    @llfunc
    def thread_is_alive(self):
        return allocate(bool)

    @attachPtr(threading.Thread, "name")
    @llfunc
    def thread_name_get(self):
        return allocate(str)

    @attachPtr(threading.Thread, "ident")
    @llfunc
    def thread_ident_get(self):
        return allocate(int)

    @attachPtr(threading.Thread, "native_id")
    @llfunc
    def thread_native_id_get(self):
        return allocate(int)

    @attachPtr(threading.Thread, "daemon")
    @llfunc
    def thread_daemon_get(self):
        return allocate(bool)

    ### Lock (primitive lock) ###
    @export
    @attachPtr(threading, "Lock")
    @llfunc
    def threading_Lock():
        return allocate(threading.Lock)

    lock_type = type(threading.Lock())

    @attachPtr(lock_type, "acquire")
    @llfunc
    def lock_acquire(self, blocking=True, timeout=-1):
        return allocate(bool)

    @attachPtr(lock_type, "release")
    @llfunc
    def lock_release(self):
        return allocate(type(None))

    @attachPtr(lock_type, "locked")
    @llfunc
    def lock_locked(self):
        return allocate(bool)

    @attachPtr(lock_type, "__enter__")
    @llfunc
    def lock__enter__(self):
        return allocate(bool)

    @attachPtr(lock_type, "__exit__")
    @llfunc
    def lock__exit__(self, exc_type, exc_val, exc_tb):
        return allocate(type(None))

    ### RLock (reentrant lock) ###
    @export
    @attachPtr(threading, "RLock")
    @llfunc
    def threading_RLock():
        return allocate(threading.RLock)

    rlock_type = type(threading.RLock())

    @attachPtr(rlock_type, "acquire")
    @llfunc
    def rlock_acquire(self, blocking=True, timeout=-1):
        return allocate(bool)

    @attachPtr(rlock_type, "release")
    @llfunc
    def rlock_release(self):
        return allocate(type(None))

    @attachPtr(rlock_type, "locked")
    @llfunc
    def rlock_locked(self):
        return allocate(bool)

    ### Condition ###
    @export
    @attachPtr(threading, "Condition")
    @llfunc
    def threading_Condition(lock=None):
        return allocate(threading.Condition)

    @attachPtr(threading.Condition, "acquire")
    @llfunc
    def condition_acquire(self, *args):
        return allocate(bool)

    @attachPtr(threading.Condition, "release")
    @llfunc
    def condition_release(self):
        return allocate(type(None))

    @attachPtr(threading.Condition, "wait")
    @llfunc
    def condition_wait(self, timeout=None):
        return allocate(bool)

    @attachPtr(threading.Condition, "wait_for")
    @llfunc
    def condition_wait_for(self, predicate, timeout=None):
        return allocate(bool)

    @attachPtr(threading.Condition, "notify")
    @llfunc
    def condition_notify(self, n=1):
        return allocate(type(None))

    @attachPtr(threading.Condition, "notify_all")
    @llfunc
    def condition_notify_all(self):
        return allocate(type(None))

    ### Semaphore ###
    @export
    @attachPtr(threading, "Semaphore")
    @llfunc
    def threading_Semaphore(value=1):
        return allocate(threading.Semaphore)

    @attachPtr(threading.Semaphore, "acquire")
    @llfunc
    def semaphore_acquire(self, blocking=True, timeout=None):
        return allocate(bool)

    @attachPtr(threading.Semaphore, "release")
    @llfunc
    def semaphore_release(self, n=1):
        return allocate(int)

    ### BoundedSemaphore ###
    @export
    @attachPtr(threading, "BoundedSemaphore")
    @llfunc
    def threading_BoundedSemaphore(value=1):
        return allocate(threading.BoundedSemaphore)

    ### Event ###
    @export
    @attachPtr(threading, "Event")
    @llfunc
    def threading_Event():
        return allocate(threading.Event)

    @attachPtr(threading.Event, "is_set")
    @llfunc
    def event_is_set(self):
        return allocate(bool)

    @attachPtr(threading.Event, "set")
    @llfunc
    def event_set(self):
        return allocate(type(None))

    @attachPtr(threading.Event, "clear")
    @llfunc
    def event_clear(self):
        return allocate(type(None))

    @attachPtr(threading.Event, "wait")
    @llfunc
    def event_wait(self, timeout=None):
        return allocate(bool)

    ### Barrier ###
    @export
    @attachPtr(threading, "Barrier")
    @llfunc
    def threading_Barrier(parties, action=None, timeout=None):
        return allocate(threading.Barrier)

    @attachPtr(threading.Barrier, "wait")
    @llfunc
    def barrier_wait(self, timeout=None):
        return allocate(int)

    @attachPtr(threading.Barrier, "reset")
    @llfunc
    def barrier_reset(self):
        return allocate(type(None))

    @attachPtr(threading.Barrier, "abort")
    @llfunc
    def barrier_abort(self):
        return allocate(type(None))

    @attachPtr(threading.Barrier, "parties")
    @llfunc
    def barrier_parties_get(self):
        return allocate(int)

    @attachPtr(threading.Barrier, "n_waiting")
    @llfunc
    def barrier_n_waiting_get(self):
        return allocate(int)

    @attachPtr(threading.Barrier, "broken")
    @llfunc
    def barrier_broken_get(self):
        return allocate(bool)

    ### Timer ###
    @export
    @attachPtr(threading, "Timer")
    @llfunc
    def threading_Timer(interval, function, args=None, kwargs=None):
        return allocate(threading.Timer)

    @attachPtr(threading.Timer, "cancel")
    @llfunc
    def timer_cancel(self):
        return allocate(type(None))

    ### Thread-local data ###
    @export
    @attachPtr(threading, "local")
    @llfunc
    def threading_local():
        return allocate(threading.local)

    ### current_thread ###
    @export
    @attachPtr(threading, "current_thread")
    @llfunc
    def threading_current_thread():
        return allocate(threading.Thread)

    ### main_thread ###
    @export
    @attachPtr(threading, "main_thread")
    @llfunc
    def threading_main_thread():
        return allocate(threading.Thread)

    ### active_count ###
    @export
    @attachPtr(threading, "active_count")
    @llfunc
    def threading_active_count():
        return allocate(int)

    ### enumerate ###
    @export
    @attachPtr(threading, "enumerate")
    @llfunc
    def threading_enumerate():
        return allocate(list)

    ### get_ident ###
    @export
    @attachPtr(threading, "get_ident")
    @llfunc
    def threading_get_ident():
        return allocate(int)

    ### get_native_id ###
    @export
    @attachPtr(threading, "get_native_id")
    @llfunc
    def threading_get_native_id():
        return allocate(int)

    ### stack_size ###
    @export
    @attachPtr(threading, "stack_size")
    @llfunc
    def threading_stack_size(size=None):
        return allocate(int)

    ### Exception types ###
    @export
    @attachPtr(threading, "ThreadError")
    @llfunc
    def threading_ThreadError(*args):
        return allocate(threading.ThreadError)

    @export
    @attachPtr(threading, "BrokenBarrierError")
    @llfunc
    def threading_BrokenBarrierError(*args):
        return allocate(threading.BrokenBarrierError)

    ### TIMEOUT_MAX ###
    @llfunc
    def threading_TIMEOUT_MAX_get():
        return allocate(float)
