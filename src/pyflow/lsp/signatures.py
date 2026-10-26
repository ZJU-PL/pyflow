"""Source-based signature help, including incomplete call expressions."""

import ast
import io
import keyword
import tokenize
from .workspace import _position_to_offset, offset_to_lsp_character


def parameters(node):
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    result = []

    def add(argument, default, kind, prefix=""):
        label = prefix + argument.arg
        if argument.annotation is not None:
            label += ": " + ast.unparse(argument.annotation)
        if default is not None:
            label += " = " + ast.unparse(default)
        result.append((argument.arg, label, kind))

    for position, (argument, default) in enumerate(zip(positional, defaults)):
        add(argument, default, "posonly" if position < len(args.posonlyargs) else "positional")
    if args.vararg:
        add(args.vararg, None, "vararg", "*")
    for argument, default in zip(args.kwonlyargs, args.kw_defaults):
        add(argument, default, "kwonly")
    if args.kwarg:
        add(args.kwarg, None, "kwarg", "**")
    return tuple(result)


def receiver_expression(tokens, end):
    """Read a primary expression backwards, across physical line breaks."""
    position = end - 1
    pairs = {")": "(", "]": "[", "}": "{"}
    while position >= 0:
        token = tokens[position]
        if token.type == tokenize.NAME and not keyword.iskeyword(token.string):
            position -= 1
        elif token.string in pairs:
            closing = [token.string]
            position -= 1
            while position >= 0 and closing:
                value = tokens[position].string
                if value in pairs:
                    closing.append(value)
                elif value == pairs[closing[-1]]:
                    closing.pop()
                position -= 1
            if closing:
                return None
            if position >= 0 and (
                tokens[position].string in pairs
                or tokens[position].type == tokenize.NAME
                and not keyword.iskeyword(tokens[position].string)
            ):
                continue
        else:
            return None
        if position >= 0 and tokens[position].string == ".":
            position -= 1
            continue
        break
    source = tokenize.untokenize(
        [(token.type, token.string) for token in tokens[position + 1 : end]]
    )
    try:
        return ast.parse(source, mode="eval").body
    except SyntaxError:
        return None


def signature_help(index, uri, line, character):
    text = index.text_for_uri(uri)
    if text is None:
        return None
    prefix = text[: _position_to_offset(text, line, character)]
    tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(prefix).readline):
            if token.type not in {
                tokenize.NL,
                tokenize.NEWLINE,
                tokenize.COMMENT,
                tokenize.INDENT,
                tokenize.DEDENT,
            }:
                tokens.append(token)
    except (tokenize.TokenError, IndentationError):
        pass
    stack = []
    for position, token in enumerate(tokens):
        if token.string in {"(", "[", "{"}:
            stack.append([position, token.string, 0, position + 1])
        elif token.string in {")", "]", "}"} and stack:
            stack.pop()
        elif token.string == "," and stack:
            stack[-1][2] += 1
            stack[-1][3] = position + 1
    frame = next(
        (
            item
            for item in reversed(stack)
            if item[1] == "("
            and item[0]
            and (
                tokens[item[0] - 1].type == tokenize.NAME
                or tokens[item[0] - 1].string in {")", "]"}
            )
        ),
        None,
    )
    if frame is None:
        return None
    bindings = index.visible_bindings_at(uri, line, character)
    expression = receiver_expression(tokens, frame[0])
    if expression is None:
        return None
    target = index._position_target(expression, bindings)
    symbol = index._resolver.callable_symbol(target)
    if symbol is None:
        return None
    if symbol.kind == 5:
        symbol = index._resolver.member(symbol.qualified_name, "__init__")
        if symbol is None:
            return None
        bound = True
    else:
        bound = symbol.binding == "class" or (
            symbol.binding == "instance"
            and isinstance(expression, ast.Attribute)
            and index._resolver.denotes_instance(index._position_target(expression.value, bindings))
        )
    signatures = index._resolver.overloads.get(symbol.qualified_name) or [symbol]
    keyword = None
    current = tokens[frame[3] :]
    if len(current) >= 2 and current[0].type == tokenize.NAME and current[1].string == "=":
        keyword = current[0].string
    result = []
    for declaration in signatures:
        values = list(declaration.parameters)
        if bound and values:
            values = values[1:]
        label = declaration.name + "("
        infos = []
        names = []
        starred = False
        for position, (name, display, kind) in enumerate(values):
            if position:
                label += ", "
            if kind == "kwonly" and not starred:
                label += "*, "
                starred = True
            if kind == "vararg":
                starred = True
            begin = offset_to_lsp_character(label, len(label))
            label += display
            infos.append({"label": [begin, offset_to_lsp_character(label, len(label))]})
            names.append(name)
            if kind == "posonly" and (
                position + 1 == len(values) or values[position + 1][2] != "posonly"
            ):
                label += ", /"
        label += ")"
        active = (
            names.index(keyword) if keyword in names else min(frame[2], max(len(values) - 1, 0))
        )
        item = {"label": label, "parameters": infos, "activeParameter": active}
        if declaration.documentation:
            item["documentation"] = {"kind": "markdown", "value": declaration.documentation}
        result.append(item)
    return (
        {
            "signatures": result,
            "activeSignature": 0,
            "activeParameter": result[0]["activeParameter"],
        }
        if result
        else None
    )
