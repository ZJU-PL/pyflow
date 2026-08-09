"""collection method support for the AST executor."""

from __future__ import annotations

import ast

from typing import Any

from ..runtime import (
    ConcolicError,
    UnsupportedSyntaxError,
    _BoolValue,
    _BytesValue,
    _CounterValue,
    _DequeValue,
    _DictValue,
    _IntValue,
    _ListValue,
    _SetValue,
    _StringValue,
    _TupleValue,
)

from ..support import _concrete


class _CollectionMethodMixin:
    def _string_method(self, value: _StringValue, name: str, args: list[Any]) -> Any:
        strings = [self._to_string(argument) for argument in args]
        if name == "startswith" and len(strings) == 1:
            return _BoolValue(
                value.concrete.startswith(strings[0].concrete),
                self._z3.PrefixOf(strings[0].symbolic, value.symbolic),
            )
        if name == "endswith" and len(strings) == 1:
            return _BoolValue(
                value.concrete.endswith(strings[0].concrete),
                self._z3.SuffixOf(strings[0].symbolic, value.symbolic),
            )
        if name in {"find", "rfind", "index", "rindex"} and 1 <= len(strings) <= 3:
            start = (
                self._as_int(args[1])
                if len(args) > 1
                else _IntValue(0, self._z3.IntVal(0))
            )
            end = self._as_int(args[2]).concrete if len(args) > 2 else None
            concrete = getattr(value.concrete, name.replace("index", "find"))(
                strings[0].concrete, start.concrete, *(() if end is None else (end,))
            )
            if name in {"index", "rindex"} and concrete == -1:
                raise ConcolicError("substring not found")
            if name == "find":
                symbolic = self._z3.IndexOf(
                    value.symbolic, strings[0].symbolic, start.symbolic
                )
            else:
                symbolic = self._z3.IntVal(concrete)
            return _IntValue(concrete, symbolic)
        if name == "count" and len(strings) == 1:
            return _IntValue(
                value.concrete.count(strings[0].concrete),
                self._z3.IntVal(value.concrete.count(strings[0].concrete)),
            )
        if name in {
            "capitalize",
            "casefold",
            "lower",
            "swapcase",
            "title",
            "upper",
        } and not args:
            concrete = getattr(value.concrete, name)()
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name in {
            "strip",
            "lstrip",
            "rstrip",
        } and len(args) <= 1:
            argument = strings[0].concrete if strings else None
            concrete = (
                getattr(value.concrete, name)(argument)
                if argument is not None
                else getattr(value.concrete, name)()
            )
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name in {"center", "ljust", "rjust", "zfill"} and 1 <= len(args) <= 2:
            width = self._as_int(args[0]).concrete
            fill = strings[1].concrete if len(args) == 2 else None
            concrete = (
                getattr(value.concrete, name)(width, fill)
                if fill is not None
                else getattr(value.concrete, name)(width)
            )
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name in {"partition", "rpartition"} and len(args) == 1:
            concrete = getattr(value.concrete, name)(strings[0].concrete)
            return _TupleValue(
                tuple(_StringValue(item, self._z3.StringVal(item)) for item in concrete)
            )
        if name in {"removeprefix", "removesuffix"} and len(args) == 1:
            concrete = getattr(value.concrete, name)(strings[0].concrete)
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name == "replace" and 2 <= len(args) <= 3:
            count = self._as_int(args[2]).concrete if len(args) == 3 else -1
            concrete = value.concrete.replace(
                strings[0].concrete, strings[1].concrete, count
            )
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name in {"split", "splitlines"}:
            if name == "splitlines":
                concrete = value.concrete.splitlines()
            else:
                separator = strings[0].concrete if strings else None
                count = self._as_int(args[1]).concrete if len(args) > 1 else -1
                concrete = value.concrete.split(separator, count)
            return _ListValue(
                [_StringValue(item, self._z3.StringVal(item)) for item in concrete]
            )
        if name == "join" and len(args) == 1:
            items = [self._to_string(item) for item in self._iter_values(args[0])]
            concrete = value.concrete.join(item.concrete for item in items)
            symbolic = self._z3.StringVal("")
            for index, item in enumerate(items):
                symbolic = (
                    symbolic
                    + (value.symbolic if index else self._z3.StringVal(""))
                    + item.symbolic
                )
            return _StringValue(concrete, symbolic)
        if name == "encode" and len(args) <= 1:
            encoding = strings[0].concrete if strings else "utf-8"
            try:
                return _BytesValue(value.concrete.encode(encoding))
            except UnicodeEncodeError as error:
                raise ConcolicError(str(error)) from error
        if name in {
            "isalnum",
            "isalpha",
            "isdigit",
            "islower",
            "isspace",
            "isupper",
        } and not args:
            return _BoolValue(
                getattr(value.concrete, name)(),
                self._z3.BoolVal(getattr(value.concrete, name)()),
            )
        raise UnsupportedSyntaxError(f"unsupported string method {name!r}")

    def _string_format(
        self, value: _StringValue, args: list[Any], keywords: dict[str, Any]
    ) -> _StringValue:
        try:
            concrete = value.concrete.format(
                *(_concrete(argument) for argument in args),
                **{name: _concrete(argument) for name, argument in keywords.items()},
            )
        except (IndexError, KeyError, ValueError) as error:
            raise ConcolicError(str(error)) from error
        return _StringValue(concrete, self._z3.StringVal(concrete))

    def _bytes_method(self, value: _BytesValue, name: str, args: list[Any]) -> Any:
        if name == "decode" and len(args) <= 1:
            try:
                encoding = self._to_string(args[0]).concrete if args else "utf-8"
                concrete = value.concrete.decode(encoding)
            except UnicodeDecodeError as error:
                raise ConcolicError(str(error)) from error
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name == "hex" and not args:
            concrete = value.concrete.hex()
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if name in {"startswith", "endswith"} and len(args) == 1:
            needle = self._to_bytes(args[0]).concrete
            concrete = getattr(value.concrete, name)(needle)
            return _BoolValue(concrete, self._z3.BoolVal(concrete))
        if name in {"find", "count"} and len(args) == 1:
            needle = self._to_bytes(args[0]).concrete
            concrete = getattr(value.concrete, name)(needle)
            return _IntValue(concrete, self._z3.IntVal(concrete))
        if name in {"split", "rsplit"} and len(args) <= 2:
            separator = self._to_bytes(args[0]).concrete if args else None
            count = self._as_int(args[1]).concrete if len(args) == 2 else -1
            concrete = getattr(value.concrete, name)(separator, count)
            return _ListValue([_BytesValue(item) for item in concrete])
        if name in {"strip", "lstrip", "rstrip"} and len(args) <= 1:
            characters = self._to_bytes(args[0]).concrete if args else None
            concrete = getattr(value.concrete, name)(characters)
            return _BytesValue(concrete)
        if name == "replace" and 2 <= len(args) <= 3:
            count = self._as_int(args[2]).concrete if len(args) == 3 else -1
            concrete = value.concrete.replace(
                self._to_bytes(args[0]).concrete,
                self._to_bytes(args[1]).concrete,
                count,
            )
            return _BytesValue(concrete)
        raise UnsupportedSyntaxError(f"unsupported bytes method {name!r}")

    def _list_method(
        self,
        value: _ListValue,
        name: str,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> Any:
        if keywords and name != "sort":
            raise UnsupportedSyntaxError(
                "keyword arguments are only supported for list.sort()"
            )
        if name == "append" and len(args) == 1:
            value.values.append(args[0])
            return None
        if name == "extend" and len(args) == 1:
            value.values.extend(self._iter_values(args[0]))
            return None
        if name == "insert" and len(args) == 2:
            value.values.insert(self._as_int(args[0]).concrete, args[1])
            return None
        if name == "pop" and len(args) <= 1:
            index = self._as_int(args[0]).concrete if args else -1
            return value.values.pop(index)
        if name == "remove" and len(args) == 1:
            for index, item in enumerate(value.values):
                if self._equals(item, args[0]).concrete:
                    value.values.pop(index)
                    return None
            raise ConcolicError("list.remove(x): x not in list")
        if name == "reverse" and not args:
            value.values.reverse()
            return None
        if name == "clear" and not args:
            value.values.clear()
            return None
        if name == "copy" and not args:
            return _ListValue(list(value.values))
        if name == "sort" and not args:
            if set(keywords) - {"key", "reverse"}:
                raise UnsupportedSyntaxError("unsupported list.sort() keyword")
            key_function = keywords.get("key")
            reverse = (
                self._truthy(keywords["reverse"]).concrete
                if "reverse" in keywords
                else False
            )
            value.values.sort(
                key=(
                    _concrete
                    if key_function is None
                    else lambda item: _concrete(
                        self._call_value(key_function, [item], {})
                    )
                ),
                reverse=reverse,
            )
            return None
        if name in {"index", "count"} and len(args) == 1:
            matches = [
                index
                for index, item in enumerate(value.values)
                if self._equals(item, args[0]).concrete
            ]
            if name == "index":
                if not matches:
                    raise ConcolicError("list.index(x): x not in list")
                return _IntValue(matches[0], self._z3.IntVal(matches[0]))
            return _IntValue(len(matches), self._z3.IntVal(len(matches)))
        raise UnsupportedSyntaxError(f"unsupported list method {name!r}")

    def _deque_method(
        self,
        value: _DequeValue,
        name: str,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> Any:
        if keywords:
            raise UnsupportedSyntaxError(
                "deque methods do not support keyword arguments"
            )
        if name == "appendleft" and len(args) == 1:
            value.values.insert(0, args[0])
            return None
        if name == "popleft" and not args:
            if not value.values:
                raise ConcolicError("pop from an empty deque")
            return value.values.pop(0)
        if name == "rotate" and len(args) <= 1:
            if value.values:
                amount = self._as_int(args[0]).concrete if args else 1
                amount %= len(value.values)
                value.values[:] = value.values[-amount:] + value.values[:-amount]
            return None
        return self._list_method(value, name, args, {})

    def _set_method(self, value: _SetValue, name: str, args: list[Any]) -> Any:
        if name == "add" and len(args) == 1:
            if not any(self._equals(item, args[0]).concrete for item in value.values):
                value.values.append(args[0])
            return None
        if name == "update" and args:
            for argument in args:
                for item in self._iter_values(argument):
                    if not any(
                        self._equals(existing, item).concrete
                        for existing in value.values
                    ):
                        value.values.append(item)
            return None
        if name in {"discard", "remove"} and len(args) == 1:
            for index, item in enumerate(value.values):
                if self._equals(item, args[0]).concrete:
                    value.values.pop(index)
                    return None
            if name == "remove":
                raise ConcolicError("set.remove(x): x not in set")
            return None
        if name == "clear" and not args:
            value.values.clear()
            return None
        if name == "copy" and not args:
            return _SetValue(list(value.values))
        raise UnsupportedSyntaxError(f"unsupported set method {name!r}")

    def _dict_method(
        self, value: _DictValue, name: str, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        if keywords and name != "update":
            raise UnsupportedSyntaxError(
                "only dict.update() supports keyword arguments"
            )
        if isinstance(value, _CounterValue) and name == "update" and len(args) == 1:
            source = args[0]
            items = (
                ((self._literal(key), count) for key, count in source.values.items())
                if isinstance(source, _DictValue)
                else ((item, self._literal(1)) for item in self._iter_values(source))
            )
            for item, count in items:
                key = self._key(item)
                previous = value.values.get(key, self._literal(0))
                value.values[key] = self._binary(previous, ast.Add(), count)
            return None
        if (
            isinstance(value, _CounterValue)
            and name == "most_common"
            and len(args) <= 1
        ):
            size = (
                self._as_int(args[0]).concrete
                if args and args[0] is not None
                else None
            )
            entries = sorted(
                value.values.items(),
                key=lambda item: self._as_int(item[1]).concrete,
                reverse=True,
            )
            if size is not None:
                entries = entries[:size]
            return _ListValue(
                [
                    _TupleValue((self._literal(key), count))
                    for key, count in entries
                ]
            )
        if isinstance(value, _CounterValue) and name == "elements" and not args:
            return _ListValue(
                [
                    self._literal(key)
                    for key, count in value.values.items()
                    for _ in range(max(self._as_int(count).concrete, 0))
                ]
            )
        if name == "get" and 1 <= len(args) <= 2:
            return value.values.get(
                self._key(args[0]), args[1] if len(args) == 2 else None
            )
        if name == "keys" and not args:
            return _ListValue([self._literal(key) for key in value.values])
        if name == "values" and not args:
            return _ListValue(list(value.values.values()))
        if name == "items" and not args:
            return _ListValue(
                [
                    _TupleValue((self._literal(key), item))
                    for key, item in value.values.items()
                ]
            )
        if name == "pop" and len(args) <= 2:
            key = self._key(args[0])
            if key in value.values:
                return value.values.pop(key)
            return args[1] if len(args) == 2 else self._missing_key(key)
        if name == "clear" and not args:
            value.values.clear()
            return None
        if name == "copy" and not args:
            return _DictValue(dict(value.values))
        if name == "setdefault" and 1 <= len(args) <= 2:
            key = self._key(args[0])
            if key not in value.values:
                value.values[key] = args[1] if len(args) == 2 else None
            return value.values[key]
        if name == "update" and len(args) <= 1:
            if args:
                source = args[0]
                if isinstance(source, _DictValue):
                    value.values.update(source.values)
                else:
                    for pair in self._iter_values(source):
                        if not isinstance(pair, (_ListValue, _TupleValue)) or len(
                            pair.values
                        ) != 2:
                            raise UnsupportedSyntaxError(
                                "dict.update() iterable items must have two values"
                            )
                        value.values[self._key(pair.values[0])] = pair.values[1]
            value.values.update(keywords)
            return None
        raise UnsupportedSyntaxError(f"unsupported dictionary method {name!r}")
