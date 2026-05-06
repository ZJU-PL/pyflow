"""
Standard library module stubs for symbolic execution.

These stubs provide minimal module content to prevent ImportError/NameError
during symbolic analysis of real code. They are NOT full implementations,
just enough structure to allow symbolic execution to continue.

All stubs must maintain soundness: over-approximate unknown behavior.
"""

from typing import Dict, Set, Any, Optional


# Module stubs: maps module name -> set of exported names
# Each exported name creates a symbolic object when accessed
STDLIB_MODULE_STUBS: Dict[str, Set[str]] = {
    # __future__ - special module for feature flags
    "__future__": {
        "annotations", "absolute_import", "division", "print_function",
        "unicode_literals", "generator_stop", "with_statement",
    },
    
    # typing - type hints (no runtime behavior, safe to stub)
    "typing": {
        "Any", "Union", "Optional", "List", "Dict", "Set", "Tuple",
        "Callable", "Iterator", "Iterable", "Sequence", "Mapping", "MutableMapping",
        "Type", "TypeVar", "Generic", "Protocol", "ClassVar",
        "Final", "Literal", "overload", "cast", "get_type_hints",
        "TYPE_CHECKING", "NoReturn", "NamedTuple", "TypedDict",
        "Awaitable", "Coroutine", "AsyncIterator", "AsyncIterable",
        "IO", "TextIO", "BinaryIO",
        # Python 3.10+ type hints
        "TypeAlias", "ParamSpec", "Concatenate", "TypeGuard",
        # Python 3.11+ type hints
        "Self", "Never", "Required", "NotRequired", "Unpack",
        "assert_type", "reveal_type", "dataclass_transform", "get_overloads",
        "clear_overloads", "get_origin", "get_args", "is_typeddict",
        # Python 3.12+ type hints
        "TypeVarTuple", "override",
    },
    
    # typing_extensions - backported and experimental type hints
    "typing_extensions": {
        "Literal", "Final", "TypedDict", "Protocol", "runtime_checkable",
        "Annotated", "ParamSpec", "Concatenate", "TypeAlias",
        "TypeGuard", "Self", "Never", "Required", "NotRequired",
        "Unpack", "dataclass_transform", "override", "deprecated",
    },
    
    # sys - system-specific parameters and functions
    "sys": {
        "argv", "stdin", "stdout", "stderr", "path", "modules",
        "version", "version_info", "platform", "executable",
        "exit", "getdefaultencoding", "getfilesystemencoding",
        "exc_info", "settrace", "gettrace", "setrecursionlimit",
        "getrecursionlimit", "maxsize", "byteorder",
    },
    
    # os - operating system interfaces
    "os": {
        "environ", "name", "path", "sep", "pathsep", "linesep",
        "getcwd", "chdir", "listdir", "mkdir", "remove", "rename",
        "walk", "system", "getenv", "putenv", "unlink", "rmdir",
    },
    
    # os.path - path operations (submodule)
    "os.path": {
        "join", "split", "splitext", "dirname", "basename",
        "exists", "isfile", "isdir", "islink", "abspath",
        "normpath", "realpath", "expanduser", "expandvars",
    },
    
    # re - regular expressions
    "re": {
        "compile", "match", "search", "findall", "finditer",
        "sub", "subn", "split", "escape", "Pattern", "Match",
        "IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE", "ASCII",
    },
    
    # json - JSON encoder/decoder
    "json": {
        "dumps", "dump", "loads", "load",
        "JSONEncoder", "JSONDecoder", "JSONDecodeError",
    },
    
    # inspect - inspect live objects
    "inspect": {
        "ismodule", "isclass", "ismethod", "isfunction", "isgeneratorfunction",
        "iscoroutinefunction", "isgenerator", "iscoroutine", "isabstract",
        "getmembers", "getmodule", "getsource", "getsourcefile",
        "signature", "Parameter", "Signature",
    },
    
    # importlib - implementation of import
    "importlib": {
        "import_module", "reload", "invalidate_caches",
        "machinery", "util", "resources", "metadata",
    },
    
    # importlib.metadata - access to package metadata
    "importlib.metadata": {
        "version", "metadata", "files", "requires", "distribution",
        "distributions", "entry_points", "PackageNotFoundError",
    },
    
    # importlib.resources - access to package resources
    "importlib.resources": {
        "read_text", "read_binary", "open_text", "open_binary",
        "path", "contents", "is_resource",
    },
    
    # math - mathematical functions
    "math": {
        "sqrt", "log", "log10", "exp", "pow", "sin", "cos", "tan",
        "asin", "acos", "atan", "atan2", "sinh", "cosh", "tanh",
        "ceil", "floor", "trunc", "fabs", "factorial", "gcd",
        "pi", "e", "tau", "inf", "nan", "isnan", "isinf", "isfinite",
    },
    
    # struct - interpret bytes as packed binary data
    "struct": {
        "pack", "unpack", "pack_into", "unpack_from",
        "calcsize", "Struct", "error",
    },
    
    # array - efficient arrays of numeric values
    "array": {
        "array",
    },
    
    # collections - container datatypes
    "collections": {
        "namedtuple", "deque", "Counter", "OrderedDict", "defaultdict",
        "ChainMap", "UserDict", "UserList", "UserString",
    },
    
    # collections.abc - abstract base classes for containers
    "collections.abc": {
        "Iterable", "Iterator", "Reversible", "Generator", "Container",
        "Hashable", "Sized", "Callable", "Collection", "Sequence",
        "MutableSequence", "Set", "MutableSet", "Mapping", "MutableMapping",
    },
    
    # abc - abstract base classes
    "abc": {
        "ABC", "ABCMeta", "abstractmethod", "abstractproperty",
        "abstractclassmethod", "abstractstaticmethod",
    },
    
    # pathlib - object-oriented filesystem paths
    "pathlib": {
        "Path", "PurePath", "PosixPath", "WindowsPath",
        "PurePosixPath", "PureWindowsPath",
    },
    
    # datetime - basic date and time types
    "datetime": {
        "date", "time", "datetime", "timedelta", "timezone",
        "tzinfo", "MINYEAR", "MAXYEAR",
    },
    
    # time - time access and conversions
    "time": {
        "time", "sleep", "clock", "perf_counter", "process_time",
        "strftime", "strptime", "localtime", "gmtime",
    },
    
    # itertools - functions creating iterators
    "itertools": {
        "count", "cycle", "repeat", "accumulate", "chain",
        "compress", "dropwhile", "filterfalse", "groupby",
        "islice", "starmap", "takewhile", "tee", "zip_longest",
        "product", "permutations", "combinations", "combinations_with_replacement",
    },
    
    # functools - higher-order functions and operations on callable objects
    "functools": {
        "reduce", "partial", "update_wrapper", "wraps",
        "lru_cache", "singledispatch", "total_ordering",
        "cached_property", "partialmethod",
    },
    
    # operator - standard operators as functions
    "operator": {
        "add", "sub", "mul", "truediv", "floordiv", "mod", "pow",
        "neg", "pos", "abs", "eq", "ne", "lt", "le", "gt", "ge",
        "and_", "or_", "xor", "not_", "itemgetter", "attrgetter",
        "methodcaller",
    },
    
    # io - core tools for working with streams
    "io": {
        "StringIO", "BytesIO", "TextIOWrapper", "BufferedReader",
        "BufferedWriter", "open", "IOBase", "RawIOBase",
    },
    
    # types - dynamic type creation and names for built-in types
    "types": {
        "FunctionType", "LambdaType", "CodeType", "FrameType",
        "ModuleType", "GeneratorType", "CoroutineType",
        "SimpleNamespace", "MappingProxyType", "TracebackType",
    },
    
    # copy - shallow and deep copy operations
    "copy": {
        "copy", "deepcopy",
    },
    
    # pickle - Python object serialization
    "pickle": {
        "dump", "dumps", "load", "loads", "Pickler", "Unpickler",
    },
    
    # enum - support for enumerations
    "enum": {
        "Enum", "IntEnum", "Flag", "IntFlag", "auto", "unique",
        "EnumMeta", "EnumCheck", "FlagBoundary", "StrEnum",
        "ReprEnum", "property", "member", "nonmember", "global_enum",
        "show_flag_values", "verify", "STRICT", "CONFORM", "EJECT", "KEEP",
    },
    
    # dataclasses - data classes
    "dataclasses": {
        "dataclass", "field", "fields", "asdict", "astuple",
        "make_dataclass", "replace", "is_dataclass",
    },
    
    # contextlib - utilities for with-statement contexts
    "contextlib": {
        "contextmanager", "asynccontextmanager", "closing", "suppress",
        "redirect_stdout", "redirect_stderr", "nullcontext",
        "ExitStack", "AsyncExitStack",
    },
    
    # warnings - warning control
    "warnings": {
        "warn", "warn_explicit", "showwarning", "formatwarning",
        "filterwarnings", "simplefilter", "resetwarnings",
        "catch_warnings",
    },
    
    # traceback - print or retrieve a stack traceback
    "traceback": {
        "print_exc", "format_exc", "print_tb", "format_tb",
        "extract_tb", "format_exception", "print_exception",
    },
    
    # logging - logging facility
    "logging": {
        "debug", "info", "warning", "error", "critical",
        "getLogger", "Logger", "Handler", "Formatter",
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL",
    },
    
    # unittest - unit testing framework
    "unittest": {
        "TestCase", "TestSuite", "TestLoader", "TextTestRunner",
        "main", "skip", "skipIf", "skipUnless", "expectedFailure",
        "mock", "Mock", "MagicMock", "patch",
    },
    
    # argparse - command-line option and argument parsing
    "argparse": {
        "ArgumentParser", "Action", "Namespace",
        "HelpFormatter", "RawDescriptionHelpFormatter",
    },
    
    # random - generate pseudo-random numbers
    "random": {
        "random", "uniform", "randint", "choice", "shuffle",
        "sample", "choices", "seed", "getstate", "setstate",
    },
    
    # string - common string operations
    "string": {
        "ascii_letters", "ascii_lowercase", "ascii_uppercase",
        "digits", "hexdigits", "octdigits", "punctuation",
        "printable", "whitespace", "Template", "Formatter",
    },
    
    # threading - thread-based parallelism
    "threading": {
        "Thread", "Lock", "RLock", "Condition", "Semaphore",
        "Event", "Timer", "Barrier", "current_thread",
        "active_count", "enumerate",
    },
    
    # multiprocessing - process-based parallelism
    "multiprocessing": {
        "Process", "Queue", "Pipe", "Pool", "Manager",
        "Lock", "RLock", "Semaphore", "Event", "Condition",
    },
    
    # asyncio - asynchronous I/O
    "asyncio": {
        "run", "create_task", "gather", "sleep", "wait",
        "Event", "Lock", "Semaphore", "Queue",
        "get_event_loop", "new_event_loop", "set_event_loop",
    },
    
    # http - HTTP modules
    "http": {
        "client", "server", "cookies", "cookiejar",
        "HTTPStatus",
    },
    
    # urllib - URL handling modules
    "urllib": {
        "request", "response", "parse", "error", "robotparser",
    },
    
    # urllib.parse - URL parsing
    "urllib.parse": {
        "urlparse", "urlunparse", "urljoin", "quote", "unquote",
        "quote_plus", "unquote_plus", "urlencode", "parse_qs",
    },
    
    # email - email and MIME handling package
    "email": {
        "message_from_string", "message_from_bytes",
        "mime", "parser", "generator", "utils",
    },
    
    # xml - XML processing
    "xml": {
        "etree", "dom", "sax", "parsers",
    },
    
    # xml.etree.ElementTree - ElementTree XML API
    "xml.etree.ElementTree": {
        "parse", "fromstring", "tostring", "Element", "SubElement",
        "ElementTree", "iterparse", "XMLParser",
    },
    
    # hashlib - secure hashes and message digests
    "hashlib": {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "blake2b", "blake2s", "new", "algorithms_available",
    },
    
    # hmac - keyed-hashing for message authentication
    "hmac": {
        "new", "digest", "compare_digest",
    },
    
    # secrets - generate secure random numbers
    "secrets": {
        "token_bytes", "token_hex", "token_urlsafe",
        "choice", "randbelow", "randbits",
    },
    
    # base64 - Base16, Base32, Base64, Base85 encoding
    "base64": {
        "b64encode", "b64decode", "b32encode", "b32decode",
        "b16encode", "b16decode", "urlsafe_b64encode", "urlsafe_b64decode",
    },
    
    # binascii - convert between binary and ASCII
    "binascii": {
        "hexlify", "unhexlify", "a2b_base64", "b2a_base64",
    },
    
    # textwrap - text wrapping and filling
    "textwrap": {
        "wrap", "fill", "shorten", "dedent", "indent",
        "TextWrapper",
    },
    
    # difflib - helpers for computing deltas
    "difflib": {
        "get_close_matches", "ndiff", "unified_diff", "context_diff",
        "SequenceMatcher", "Differ", "HtmlDiff",
    },
    
    # pprint - data pretty printer
    "pprint": {
        "pprint", "pformat", "isreadable", "isrecursive",
        "PrettyPrinter",
    },
    
    # locale - internationalization services
    "locale": {
        "getlocale", "setlocale", "localeconv", "getdefaultlocale",
        "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME", "LC_MONETARY",
    },
    
    # codecs - codec registry and base classes
    "codecs": {
        "encode", "decode", "open", "EncodedFile", "getencoder", "getdecoder",
        "getreader", "getwriter", "register", "lookup",
        "utf_8_encode", "utf_8_decode", "ascii_encode", "ascii_decode",
        "latin_1_encode", "latin_1_decode", "BOM_UTF8", "BOM_UTF16",
    },
    
    # gettext - multilingual internationalization services
    "gettext": {
        "gettext", "ngettext", "translation", "install",
    },
    
    # socket - low-level networking interface
    "socket": {
        "socket", "create_connection", "create_server",
        "gethostname", "gethostbyname", "getaddrinfo",
        "AF_INET", "AF_INET6", "SOCK_STREAM", "SOCK_DGRAM",
    },
    
    # ssl - TLS/SSL wrapper for socket objects
    "ssl": {
        "wrap_socket", "create_default_context", "SSLContext",
        "SSLSocket", "PROTOCOL_TLS", "CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED",
    },
    
    # select - waiting for I/O completion
    "select": {
        "select", "poll", "epoll", "kqueue",
    },
    
    # subprocess - subprocess management
    "subprocess": {
        "run", "Popen", "call", "check_call", "check_output",
        "PIPE", "STDOUT", "DEVNULL", "TimeoutExpired", "CalledProcessError",
    },
    
    # shutil - high-level file operations
    "shutil": {
        "copy", "copy2", "copyfile", "copytree", "move",
        "rmtree", "make_archive", "unpack_archive", "which",
    },
    
    # tempfile - generate temporary files and directories
    "tempfile": {
        "TemporaryFile", "NamedTemporaryFile", "SpooledTemporaryFile",
        "TemporaryDirectory", "mkstemp", "mkdtemp", "gettempdir",
    },
    
    # glob - Unix style pathname pattern expansion
    "glob": {
        "glob", "iglob", "escape",
    },
    
    # fnmatch - Unix filename pattern matching
    "fnmatch": {
        "fnmatch", "fnmatchcase", "filter", "translate",
    },
    
    # zipfile - work with ZIP archives
    "zipfile": {
        "ZipFile", "ZipInfo", "is_zipfile",
        "ZIP_STORED", "ZIP_DEFLATED", "ZIP_BZIP2", "ZIP_LZMA",
    },
    
    # tarfile - read and write tar archive files
    "tarfile": {
        "open", "TarFile", "TarInfo", "is_tarfile",
    },
    
    # csv - CSV file reading and writing
    "csv": {
        "reader", "writer", "DictReader", "DictWriter",
        "Sniffer", "excel", "excel_tab", "unix_dialect",
    },
    
    # configparser - configuration file parser
    "configparser": {
        "ConfigParser", "RawConfigParser", "SafeConfigParser",
    },
    
    # sqlite3 - DB-API 2.0 interface for SQLite databases
    "sqlite3": {
        "connect", "Connection", "Cursor", "Row",
        "Error", "DatabaseError", "IntegrityError",
    },
    
    # zlib - compression compatible with gzip
    "zlib": {
        "compress", "decompress", "compressobj", "decompressobj",
        "crc32", "adler32",
    },
    
    # gzip - support for gzip files
    "gzip": {
        "open", "compress", "decompress", "GzipFile",
    },
    
    # bz2 - support for bzip2 compression
    "bz2": {
        "open", "compress", "decompress", "BZ2File",
    },
    
    # lzma - compression using the LZMA algorithm
    "lzma": {
        "open", "compress", "decompress", "LZMAFile",
    },
    
    # colorsys - conversions between color systems
    "colorsys": {
        "rgb_to_yiq", "yiq_to_rgb", "rgb_to_hls", "hls_to_rgb",
        "rgb_to_hsv", "hsv_to_rgb",
    },
    
    # fractions - rational numbers
    "fractions": {
        "Fraction",
    },
    
    # decimal - decimal fixed point and floating point arithmetic
    "decimal": {
        "Decimal", "getcontext", "setcontext", "localcontext",
        "Context", "ROUND_UP", "ROUND_DOWN", "ROUND_CEILING",
    },
    
    # numbers - numeric abstract base classes
    "numbers": {
        "Number", "Complex", "Real", "Rational", "Integral",
    },
    
    # cmath - mathematical functions for complex numbers
    "cmath": {
        "sqrt", "exp", "log", "log10", "sin", "cos", "tan",
        "asin", "acos", "atan", "sinh", "cosh", "tanh",
        "pi", "e", "tau", "inf", "nan", "phase", "polar", "rect",
    },
    
    # statistics - mathematical statistics functions
    "statistics": {
        "mean", "median", "mode", "stdev", "variance",
        "quantiles", "fmean", "geometric_mean", "harmonic_mean",
    },
    
    # platform - access to underlying platform's identifying data
    "platform": {
        "system", "release", "version", "machine", "processor",
        "python_version", "python_implementation",
    },
    
    # ctypes - foreign function library
    "ctypes": {
        "c_int", "c_long", "c_char", "c_char_p", "c_void_p",
        "CDLL", "windll", "cdll", "POINTER", "pointer",
    },
    
    # weakref - weak references
    "weakref": {
        "ref", "proxy", "WeakKeyDictionary", "WeakValueDictionary",
        "WeakSet", "finalize",
    },
    
    # gc - garbage collector interface
    "gc": {
        "collect", "get_objects", "get_referrers", "get_referents",
        "disable", "enable", "isenabled", "set_debug", "get_debug",
    },
    
    # atexit - exit handlers
    "atexit": {
        "register", "unregister",
    },
    
    # signal - set handlers for asynchronous events
    "signal": {
        "signal", "getsignal", "alarm", "pause",
        "SIGINT", "SIGTERM", "SIGHUP", "SIGKILL",
    },
    
    # code - interpreter base classes
    "code": {
        "compile_command", "InteractiveInterpreter", "InteractiveConsole",
    },
    
    # dis - disassembler of Python bytecode
    "dis": {
        "dis", "disassemble", "get_instructions", "show_code",
        "Instruction", "Bytecode",
    },
    
    # ast - abstract syntax trees
    "ast": {
        "parse", "literal_eval", "dump", "walk",
        "NodeVisitor", "NodeTransformer", "fix_missing_locations",
    },
    
    # textwrap - text wrapping and filling
    "textwrap": {
        "wrap", "fill", "shorten", "dedent", "indent",
        "TextWrapper",
    },
    
    # string - common string operations
    "string": {
        "ascii_letters", "ascii_lowercase", "ascii_uppercase",
        "digits", "hexdigits", "octdigits", "punctuation",
        "printable", "whitespace", "Template", "Formatter",
    },
    
    # uuid - UUID objects
    "uuid": {
        "uuid1", "uuid3", "uuid4", "uuid5", "UUID",
        "NAMESPACE_DNS", "NAMESPACE_URL", "NAMESPACE_OID", "NAMESPACE_X500",
    },
    
    # errno - standard errno system symbols
    "errno": {
        "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO",
        "E2BIG", "ENOEXEC", "EBADF", "ECHILD", "EAGAIN",
        "ENOMEM", "EACCES", "EFAULT", "EBUSY", "EEXIST",
        "ENOTDIR", "EISDIR", "EINVAL", "EMFILE", "ENOSPC",
        "errorcode",
    },
    
    # keyword - testing for Python keywords
    "keyword": {
        "iskeyword", "kwlist", "issoftkeyword", "softkwlist",
    },
    
    # linecache - random access to text lines
    "linecache": {
        "getline", "clearcache", "checkcache", "lazycache",
    },
    
    # queue - synchronized queue class
    "queue": {
        "Queue", "PriorityQueue", "LifoQueue", "SimpleQueue",
        "Empty", "Full",
    },
    
    # reprlib - alternate repr() implementation
    "reprlib": {
        "repr", "Repr", "recursive_repr",
    },
    
    # tokenize - tokenizer for Python source
    "tokenize": {
        "tokenize", "generate_tokens", "untokenize",
        "TokenInfo", "COMMENT", "NL", "NEWLINE", "INDENT",
        "DEDENT", "NAME", "NUMBER", "STRING", "OP",
    },
    
    # token - constants for Python parse trees
    "token": {
        "tok_name", "ISTERMINAL", "ISNONTERMINAL", "ISEOF",
        "NAME", "NUMBER", "STRING", "NEWLINE", "INDENT",
        "DEDENT", "LPAR", "RPAR", "LSQB", "RSQB", "COLON",
        "COMMA", "SEMI", "PLUS", "MINUS", "STAR", "SLASH",
        "VBAR", "AMPER", "LESS", "GREATER", "EQUAL", "DOT",
    },
    
    # weakref - weak references
    "weakref": {
        "ref", "proxy", "WeakValueDictionary", "WeakKeyDictionary",
        "WeakSet", "finalize", "ReferenceType", "ProxyType",
    },
    
    # secrets - generate secure random numbers for managing secrets
    "secrets": {
        "token_bytes", "token_hex", "token_urlsafe",
        "choice", "randbelow", "randbits",
        "compare_digest",
    },
    
    # base64 - RFC 3548: Base16, Base32, Base64 data encodings
    "base64": {
        "b64encode", "b64decode", "standard_b64encode", "standard_b64decode",
        "urlsafe_b64encode", "urlsafe_b64decode",
        "b32encode", "b32decode", "b16encode", "b16decode",
        "a85encode", "a85decode", "b85encode", "b85decode",
    },
    
    # shutil - high-level file operations
    "shutil": {
        "copyfile", "copymode", "copystat", "copy", "copy2",
        "copytree", "rmtree", "move", "disk_usage",
        "make_archive", "unpack_archive", "get_archive_formats",
        "which", "chown",
    },
    
    # tempfile - generate temporary files and directories
    "tempfile": {
        "TemporaryFile", "NamedTemporaryFile", "SpooledTemporaryFile",
        "TemporaryDirectory", "mkstemp", "mkdtemp", "mktemp",
        "gettempdir", "gettempprefix",
    },
    
    # zipfile - work with ZIP archives
    "zipfile": {
        "ZipFile", "PyZipFile", "ZipInfo",
        "is_zipfile", "ZIP_STORED", "ZIP_DEFLATED",
        "ZIP_BZIP2", "ZIP_LZMA", "BadZipFile",
    },
    
    # tarfile - read and write tar archive files
    "tarfile": {
        "open", "TarFile", "TarInfo",
        "is_tarfile", "TarError", "ReadError", "CompressionError",
    },
    
    # bz2 - support for bzip2 compression
    "bz2": {
        "compress", "decompress", "BZ2File", "BZ2Compressor", "BZ2Decompressor",
    },
    
    # sqlite3 - DB-API 2.0 interface for SQLite databases
    "sqlite3": {
        "connect", "Connection", "Cursor", "Row",
        "Error", "DatabaseError", "IntegrityError",
        "PARSE_DECLTYPES", "PARSE_COLNAMES",
    },
    
    # threading - thread-based parallelism
    "threading": {
        "Thread", "Lock", "RLock", "Condition", "Semaphore",
        "BoundedSemaphore", "Event", "Timer", "Barrier",
        "local", "current_thread", "active_count", "enumerate",
    },
    
    # multiprocessing - process-based parallelism
    "multiprocessing": {
        "Process", "Queue", "Pipe", "Pool", "Manager",
        "Value", "Array", "Lock", "RLock", "Semaphore",
        "Event", "Condition", "Barrier", "cpu_count",
    },
    
    # socket - low-level networking interface
    "socket": {
        "socket", "create_connection", "create_server",
        "getfqdn", "gethostbyname", "gethostname",
        "AF_INET", "AF_INET6", "SOCK_STREAM", "SOCK_DGRAM",
        "SOL_SOCKET", "SO_REUSEADDR", "error", "timeout",
    },
    
    # select - waiting for I/O completion
    "select": {
        "select", "poll", "epoll", "kqueue", "kevent",
        "POLLIN", "POLLOUT", "POLLERR",
    },
    
    # pprint - data pretty printer
    "pprint": {
        "pprint", "pformat", "pp", "PrettyPrinter",
        "isreadable", "isrecursive", "saferepr",
    },
}


# Special module attributes with concrete/semi-concrete values
# These are attributes that should NOT be havoced, as they have predictable behavior
SPECIAL_MODULE_ATTRIBUTES: Dict[str, Dict[str, Any]] = {
    "sys": {
        # sys.version_info is a named tuple with major, minor, micro, releaselevel, serial
        # Should be treated as concrete tuple for version checks
        "version_info": {
            "type": "version_info",  # Special marker
            "description": "Python version tuple (major, minor, micro, releaselevel, serial)",
        },
        # sys.maxsize is a concrete integer
        "maxsize": {
            "type": "int",
            "concrete": True,
            "description": "Maximum integer value",
        },
        # sys.platform is a concrete string
        "platform": {
            "type": "str",
            "concrete": True,
            "description": "Platform identifier string",
        },
    },
    "os": {
        # os.environ is a dict-like object mapping strings to strings
        # Should NOT be fully havoced - it's a dict with string keys/values
        "environ": {
            "type": "environ",  # Special marker
            "description": "Environment variables dict-like mapping",
        },
        # os.name is a concrete string
        "name": {
            "type": "str",
            "concrete": True,
            "description": "Operating system name",
        },
    },
    # Exception base classes - always available in builtins
    "builtins": {
        "Exception": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception"],
            "description": "Base class for most exceptions",
        },
        "BaseException": {
            "type": "exception_class",
            "hierarchy": ["BaseException"],
            "description": "Root exception class",
        },
        "TypeError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "TypeError"],
            "description": "Inappropriate type",
        },
        "ValueError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "ValueError"],
            "description": "Inappropriate value",
        },
        "IndexError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "LookupError", "IndexError"],
            "description": "Sequence index out of range",
        },
        "KeyError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "LookupError", "KeyError"],
            "description": "Mapping key not found",
        },
        "AttributeError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "AttributeError"],
            "description": "Attribute not found",
        },
        "NameError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "NameError"],
            "description": "Name not found in scope",
        },
        "RuntimeError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "RuntimeError"],
            "description": "Generic runtime error",
        },
        "AssertionError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "AssertionError"],
            "description": "Assertion failed",
        },
        "ZeroDivisionError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "ArithmeticError", "ZeroDivisionError"],
            "description": "Division by zero",
        },
        "StopIteration": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "StopIteration"],
            "description": "Iterator exhausted",
        },
        "RecursionError": {
            "type": "exception_class",
            "hierarchy": ["BaseException", "Exception", "RuntimeError", "RecursionError"],
            "description": "Maximum recursion depth exceeded",
        },
    },
}


def get_module_exports(module_name: str) -> Set[str]:
    """
    Get the set of exported names for a stdlib module.
    
    Returns an empty set if the module is not in our stubs
    (indicating it's unknown and should be havoced).
    """
    return STDLIB_MODULE_STUBS.get(module_name, set())


def is_known_stdlib_module(module_name: str) -> bool:
    """Check if a module has a stub definition."""
    return module_name in STDLIB_MODULE_STUBS


def get_special_attribute(module_name: str, attr_name: str) -> Optional[Dict[str, Any]]:
    """
    Get special attribute information for module.attr access.
    
    Returns metadata dict if this is a special attribute that should
    NOT be havoced (e.g., sys.version_info, os.environ), otherwise None.
    """
    if module_name in SPECIAL_MODULE_ATTRIBUTES:
        return SPECIAL_MODULE_ATTRIBUTES[module_name].get(attr_name)
    return None
