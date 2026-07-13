class JSONDecodeError(ValueError):
    def __init__(self, msg, doc, pos):
        self.msg = msg
        self.doc = doc
        self.pos = pos


class JSONEncoder:
    def __init__(self, skipkeys=False, ensure_ascii=True, check_circular=True,
                 allow_nan=True, sort_keys=False, indent=None, separators=None,
                 default=None):
        self.skipkeys = skipkeys
        self.ensure_ascii = ensure_ascii
        self.check_circular = check_circular
        self.allow_nan = allow_nan
        self.sort_keys = sort_keys
        self.indent = indent
        self.separators = separators
        self.default = default

    def encode(self, o):
        return str(o)

    def iterencode(self, o):
        return [self.encode(o)]


class JSONDecoder:
    def __init__(self, object_hook=None, parse_float=None, parse_int=None,
                 parse_constant=None, strict=True, object_pairs_hook=None):
        self.object_hook = object_hook
        self.parse_float = parse_float
        self.parse_int = parse_int
        self.parse_constant = parse_constant
        self.strict = strict
        self.object_pairs_hook = object_pairs_hook

    def decode(self, s):
        return {"_json_str": s}


def loads(s, cls=None, object_hook=None, parse_float=None, parse_int=None,
          parse_constant=None, object_pairs_hook=None):
    if cls:
        decoder = cls(object_hook=object_hook, parse_float=parse_float,
                     parse_int=parse_int, parse_constant=parse_constant,
                     object_pairs_hook=object_pairs_hook)
        return decoder.decode(s)
    return {"_json_str": s}


def dumps(obj, skipkeys=False, ensure_ascii=True, check_circular=True,
          allow_nan=True, cls=None, indent=None, separators=None, default=None,
          sort_keys=False):
    if cls:
        encoder = cls(skipkeys=skipkeys, ensure_ascii=ensure_ascii,
                     check_circular=check_circular, allow_nan=allow_nan,
                     sort_keys=sort_keys, indent=indent, separators=separators,
                     default=default)
        return encoder.encode(obj)
    return str(obj)


def load(fp, cls=None, object_hook=None, parse_float=None, parse_int=None,
         parse_constant=None, object_pairs_hook=None):
    s = fp.read()
    return loads(s, cls=cls, object_hook=object_hook, parse_float=parse_float,
                parse_int=parse_int, parse_constant=parse_constant,
                object_pairs_hook=object_pairs_hook)


def dump(obj, fp, skipkeys=False, ensure_ascii=True, check_circular=True,
         allow_nan=True, cls=None, indent=None, separators=None, default=None,
         sort_keys=False):
    s = dumps(obj, skipkeys=skipkeys, ensure_ascii=ensure_ascii,
             check_circular=check_circular, allow_nan=allow_nan, cls=cls,
             indent=indent, separators=separators, default=default,
             sort_keys=sort_keys)
    fp.write(s)
    return None
