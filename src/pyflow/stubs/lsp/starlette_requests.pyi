from starlette.datastructures import State

class HTTPConnection:
    @property
    def state(self) -> State: ...

class Request(HTTPConnection): ...
