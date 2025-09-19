from . import interface


class Program(object):
    __slots__ = "interface", "storeGraph", "entryPoints", "liveCode", "stats"

    def __init__(self):
        self.interface = interface.InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
