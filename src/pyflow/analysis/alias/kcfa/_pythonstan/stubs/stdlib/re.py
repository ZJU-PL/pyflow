class Match:
    def __init__(self, pattern, string, pos=0, endpos=None):
        self.re = pattern
        self.string = string
        self.pos = pos
        self.endpos = endpos if endpos is not None else len(string)
        self.lastindex = 0
        self.lastgroup = None

    def group(self, *args):
        if not args:
            return self.string
        if len(args) == 1:
            return self.string
        return tuple([self.string] * len(args))

    def groups(self, default=None):
        return (self.string,)

    def groupdict(self, default=None):
        return {}

    def start(self, group=0):
        return self.pos

    def end(self, group=0):
        return self.endpos

    def span(self, group=0):
        return (self.pos, self.endpos)

    def expand(self, template):
        return template


class Pattern:
    def __init__(self, pattern, flags=0):
        self.pattern = pattern
        self.flags = flags
        self.groups = 0
        self.groupindex = {}

    def match(self, string, pos=0, endpos=None):
        return Match(self, string, pos, endpos)

    def fullmatch(self, string, pos=0, endpos=None):
        return Match(self, string, pos, endpos)

    def search(self, string, pos=0, endpos=None):
        return Match(self, string, pos, endpos)

    def findall(self, string, pos=0, endpos=None):
        return [string]

    def finditer(self, string, pos=0, endpos=None):
        return [Match(self, string, pos, endpos)]

    def split(self, string, maxsplit=0):
        return [string]

    def sub(self, repl, string, count=0):
        if callable(repl):
            return repl(Match(self, string))
        return repl

    def subn(self, repl, string, count=0):
        result = self.sub(repl, string, count)
        return (result, 1)


def compile(pattern, flags=0):
    return Pattern(pattern, flags)


def match(pattern, string, flags=0):
    return Pattern(pattern, flags).match(string)


def fullmatch(pattern, string, flags=0):
    return Pattern(pattern, flags).fullmatch(string)


def search(pattern, string, flags=0):
    return Pattern(pattern, flags).search(string)


def findall(pattern, string, flags=0):
    return Pattern(pattern, flags).findall(string)


def finditer(pattern, string, flags=0):
    return Pattern(pattern, flags).finditer(string)


def split(pattern, string, maxsplit=0, flags=0):
    return Pattern(pattern, flags).split(string, maxsplit)


def sub(pattern, repl, string, count=0, flags=0):
    return Pattern(pattern, flags).sub(repl, string, count)


def subn(pattern, repl, string, count=0, flags=0):
    return Pattern(pattern, flags).subn(repl, string, count)


def escape(pattern):
    return pattern


def purge():
    return None


IGNORECASE = I = 2
LOCALE = L = 4
MULTILINE = M = 8
DOTALL = S = 16
UNICODE = U = 32
VERBOSE = X = 64
ASCII = A = 256


class error(Exception):
    pass
