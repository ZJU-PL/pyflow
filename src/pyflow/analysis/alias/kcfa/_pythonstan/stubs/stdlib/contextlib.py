class _ContextManager:
    def __init__(self, value):
        self._value = value

    def __enter__(self):
        return self._value

    def __exit__(self, exc_type, exc, tb):
        return False


def contextmanager(func):
    def wrapper(*args, **kwargs):
        gen = func(*args, **kwargs)
        return _ContextManager(next(gen))
    wrapper.__wrapped__ = func
    return wrapper


class suppress:
    def __init__(self, *exceptions):
        self._exceptions = exceptions

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, self._exceptions)


class redirect_stdout:
    def __init__(self, target):
        self._target = target

    def __enter__(self):
        return self._target

    def __exit__(self, exc_type, exc, tb):
        return False


class redirect_stderr:
    def __init__(self, target):
        self._target = target

    def __enter__(self):
        return self._target

    def __exit__(self, exc_type, exc, tb):
        return False


class closing:
    def __init__(self, thing):
        self._thing = thing

    def __enter__(self):
        return self._thing

    def __exit__(self, exc_type, exc, tb):
        return False


class ExitStack:
    def __init__(self):
        self._stack = []

    def enter_context(self, cm):
        result = cm.__enter__()
        self._stack.append(cm)
        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class AsyncExitStack:
    def __init__(self):
        self._stack = []

    async def enter_async_context(self, cm):
        result = await cm.__aenter__()
        self._stack.append(cm)
        return result

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class asynccontextmanager:
    def __init__(self, func):
        self.func = func
        self.__wrapped__ = func

    def __call__(self, *args, **kwargs):
        return _AsyncContextManager(self.func(*args, **kwargs))


class _AsyncContextManager:
    def __init__(self, gen):
        self._gen = gen

    async def __aenter__(self):
        return await self._gen.__anext__()

    async def __aexit__(self, exc_type, exc, tb):
        return False
