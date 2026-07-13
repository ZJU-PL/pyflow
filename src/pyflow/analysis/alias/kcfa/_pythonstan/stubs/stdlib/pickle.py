HIGHEST_PROTOCOL = 5
DEFAULT_PROTOCOL = 4


class PickleError(Exception):
    pass


class PicklingError(PickleError):
    pass


class UnpicklingError(PickleError):
    pass


class _Pickler:
    def __init__(self, file, protocol=None, fix_imports=True, buffer_callback=None):
        self._file = file
        self.protocol = protocol if protocol is not None else DEFAULT_PROTOCOL
        self.fix_imports = fix_imports
        self.buffer_callback = buffer_callback
        self.memo = {}
        self.fast = 0

    def dump(self, obj):
        self._file.write(b'\x80')
        self._obj = obj

    def clear_memo(self):
        self.memo.clear()

    def persistent_id(self, obj):
        return None


class _Unpickler:
    def __init__(self, file, fix_imports=True, encoding='ASCII', errors='strict',
                 buffers=None):
        self._file = file
        self.fix_imports = fix_imports
        self.encoding = encoding
        self.errors = errors
        self.buffers = buffers
        self.memo = {}

    def load(self):
        data = self._file.read()
        return {"_pickled_": data}

    def find_class(self, module, name):
        return type(name, (), {})

    def persistent_load(self, pid):
        raise UnpicklingError("persistent_load")


Pickler = _Pickler
Unpickler = _Unpickler


def dump(obj, file, protocol=None, fix_imports=True, buffer_callback=None):
    _Pickler(file, protocol, fix_imports, buffer_callback).dump(obj)


def dumps(obj, protocol=None, fix_imports=True, buffer_callback=None):
    return b'\x80' + repr(obj).encode()


def load(file, fix_imports=True, encoding='ASCII', errors='strict', buffers=None):
    return _Unpickler(file, fix_imports, encoding, errors, buffers).load()


def loads(data, fix_imports=True, encoding='ASCII', errors='strict', buffers=None):
    return {"_pickled_": data}


def encode_long(x):
    return x.to_bytes((x.bit_length() + 8) // 8, 'little', signed=True)


def decode_long(data):
    return int.from_bytes(data, 'little', signed=True)


MARK = b'('
STOP = b'.'
POP = b'0'
POP_MARK = b'1'
DUP = b'2'
FLOAT = b'F'
INT = b'I'
BININT = b'J'
BININT1 = b'K'
LONG = b'L'
BININT2 = b'M'
NONE = b'N'
PERSID = b'P'
BINPERSID = b'Q'
REDUCE = b'R'
STRING = b'S'
BINSTRING = b'T'
SHORT_BINSTRING = b'U'
UNICODE = b'V'
BINUNICODE = b'X'
APPEND = b'a'
BUILD = b'b'
GLOBAL = b'c'
DICT = b'd'
EMPTY_DICT = b'}'
APPENDS = b'e'
GET = b'g'
BINGET = b'h'
INST = b'i'
LONG_BINGET = b'j'
LIST = b'l'
EMPTY_LIST = b']'
OBJ = b'o'
PUT = b'p'
BINPUT = b'q'
LONG_BINPUT = b'r'
SETITEM = b's'
TUPLE = b't'
EMPTY_TUPLE = b')'
SETITEMS = b'u'
BINFLOAT = b'G'
PROTO = b'\x80'
NEWOBJ = b'\x81'
EXT1 = b'\x82'
EXT2 = b'\x83'
EXT4 = b'\x84'
TUPLE1 = b'\x85'
TUPLE2 = b'\x86'
TUPLE3 = b'\x87'
NEWTRUE = b'\x88'
NEWFALSE = b'\x89'
LONG1 = b'\x8a'
LONG4 = b'\x8b'
BINBYTES = b'B'
SHORT_BINBYTES = b'C'
SHORT_BINUNICODE = b'\x8c'
BINUNICODE8 = b'\x8d'
BINBYTES8 = b'\x8e'
EMPTY_SET = b'\x8f'
ADDITEMS = b'\x90'
FROZENSET = b'\x91'
NEWOBJ_EX = b'\x92'
STACK_GLOBAL = b'\x93'
MEMOIZE = b'\x94'
FRAME = b'\x95'
BYTEARRAY8 = b'\x96'
NEXT_BUFFER = b'\x97'
READONLY_BUFFER = b'\x98'
