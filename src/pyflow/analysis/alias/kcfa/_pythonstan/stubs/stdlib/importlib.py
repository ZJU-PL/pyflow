class ModuleSpec:
    def __init__(self, name, loader, origin=None, is_package=False):
        self.name = name
        self.loader = loader
        self.origin = origin
        self.submodule_search_locations = [] if is_package else None
        self.cached = None
        self.parent = name.rpartition('.')[0] if '.' in name else ''


class _Module:
    def __init__(self, name):
        self.__name__ = name
        self.__spec__ = None
        self.__loader__ = None
        self.__package__ = None
        self.__path__ = None
        self.__file__ = None


def import_module(name, package=None):
    mod = _Module(name)
    mod.__package__ = package
    return mod


def find_loader(name, path=None):
    return _Loader(name)


def find_spec(name, package=None, target=None):
    return ModuleSpec(name, _Loader(name))


def reload(module):
    return module


def invalidate_caches():
    pass


class _Loader:
    def __init__(self, name):
        self.name = name

    def load_module(self, fullname):
        return _Module(fullname)

    def exec_module(self, module):
        pass

    def create_module(self, spec):
        return _Module(spec.name)


def util_find_spec(name, package=None):
    return ModuleSpec(name, _Loader(name))


def util_module_from_spec(spec):
    mod = _Module(spec.name)
    mod.__spec__ = spec
    mod.__loader__ = spec.loader
    return mod


def util_spec_from_loader(name, loader, origin=None, is_package=None):
    return ModuleSpec(name, loader, origin, is_package or False)


def util_spec_from_file_location(name, location=None, loader=None, submodule_search_locations=None):
    spec = ModuleSpec(name, loader or _Loader(name), origin=location)
    spec.submodule_search_locations = submodule_search_locations
    return spec


def resources_files(package):
    return _Traversable(package)


def resources_as_file(traversable):
    return traversable


class _Traversable:
    def __init__(self, package):
        self._package = package

    def joinpath(self, *descendants):
        return _Traversable(self._package)

    def __truediv__(self, child):
        return self.joinpath(child)

    def read_text(self, encoding=None):
        return ""

    def read_bytes(self):
        return b""

    def is_dir(self):
        return False

    def is_file(self):
        return True

    def iterdir(self):
        return iter([])

    def open(self, mode='r', *args, **kwargs):
        return _FileHandle(self)


class _FileHandle:
    def __init__(self, traversable):
        self._traversable = traversable

    def read(self):
        return self._traversable.read_text()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False
