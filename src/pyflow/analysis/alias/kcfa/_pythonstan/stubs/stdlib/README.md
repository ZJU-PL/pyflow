# Standard Library Stubs for Pointer Analysis

This directory contains Python source stubs used by the import resolver for pointer analysis.

Location: `/stubs/stdlib/` (project root)

## Mapping Rule

Module name `a.b.c` maps to `stubs/stdlib/a/b/c.py` or `stubs/stdlib/a/b/c/__init__.py`.

## Precedence

- Builtins (`sys.builtin_module_names`) are never mocked.
- Default (`mock_libs=True`, `prefer_mock_libs=False`): resolve real modules first, then fall back to mocks.
- Prefer mock (`prefer_mock_libs=True`): use mocks when present, otherwise resolve real modules.

## Available Tier 1 Mock Libraries

High-precision mocks for common stdlib modules:

### Core Utilities
- `functools` - Partial application, decorators (lru_cache, wraps, etc.)
- `contextlib` - Context managers (contextmanager, suppress, ExitStack, etc.)
- `copy` - Shallow and deep copy operations
- `itertools` - Iterator building blocks (chain, groupby, product, etc.)
- `collections` - Container datatypes (Counter, defaultdict, deque, etc.)

### I/O and File Operations
- `os` - Operating system interfaces (path operations, environment, etc.)
- `pathlib` - Object-oriented filesystem paths
- `shutil` - High-level file operations (copy, move, archive, etc.)
- `tempfile` - Temporary files and directories
- `glob` - Unix-style pathname pattern expansion
- `fnmatch` - Unix filename pattern matching

### Data Formats and Patterns
- `json` - JSON encoder and decoder
- `re` - Regular expression operations (compile, match, search, etc.)

### Time and Date
- `datetime` - Date and time types (datetime, date, time, timedelta)
- `time` - Time access and conversions

### Security and Cryptography
- `hashlib` - Secure hash and message digest algorithms
- `hmac` - Keyed-hashing for message authentication
- `secrets` - Generate secure random numbers for secrets
- `base64` - Base64 encoding/decoding
- `uuid` - UUID generation

### Logging
- `logging` - Flexible event logging system

## Available Tier 2 Mock Libraries

High-frequency utilities and framework-adjacent modules:

### Type System and Introspection
- `importlib` - Module import utilities (import_module, find_spec, resources)
- `inspect` - Inspect live objects (signature, getmembers, stack, etc.)
- `types` - Dynamic type creation (ModuleType, FunctionType, SimpleNamespace, etc.)
- `enum` - Enumeration support (Enum, IntEnum, Flag, auto, etc.)
- `dataclasses` - Data class decorators (dataclass, field, asdict, etc.)
- `abc` - Abstract base classes (ABC, ABCMeta, abstractmethod, etc.)

### Network and Web
- `urllib.parse` - URL parsing utilities (urlparse, urljoin, quote, etc.)
- `http` - HTTP status codes, methods, and connection classes
- `email` - Email message handling (Message, MIME types, parsers)
- `mimetypes` - Map filenames to MIME types

### I/O and Serialization
- `io` - Core I/O operations (StringIO, BytesIO, TextIOWrapper, etc.)
- `csv` - CSV file reading and writing (reader, writer, DictReader, etc.)
- `pickle` - Object serialization (dump, load, Pickler, Unpickler)

### Debugging and Diagnostics
- `warnings` - Warning control (warn, filterwarnings, catch_warnings)
- `traceback` - Traceback utilities (format_exc, StackSummary, etc.)

### Algorithms and Math
- `operator` - Standard operators as functions (itemgetter, attrgetter, etc.)
- `math` - Mathematical functions (sqrt, sin, cos, floor, ceil, etc.)
- `random` - Random number generation (Random, choice, shuffle, etc.)
- `heapq` - Heap queue algorithm (heappush, heappop, nlargest, etc.)
- `bisect` - Array bisection algorithm (bisect_left, insort, etc.)

### Memory Management
- `weakref` - Weak references (ref, proxy, WeakValueDictionary, etc.)

## Precision Design Principles

All mocks follow high-precision guidelines for pointer analysis:

1. **Preserve dataflow**: Functions return values derived from inputs, not opaque constants
2. **Preserve call graphs**: Decorators and wrappers maintain __wrapped__ and call the wrapped function
3. **Preserve aliasing semantics**: Functions returning views return inputs; functions returning copies allocate new objects
4. **Model key types**: Classes for Pattern, Match, Logger, Path, etc. with minimal but flow-preserving methods
5. **No defensive programming**: No hasattr checks, no silent defaults, fail fast
