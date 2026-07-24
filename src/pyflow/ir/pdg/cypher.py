"""
In-memory Cypher-like querying for Program Dependence Graphs (PDG).

This module implements a small, production-oriented subset of Cypher that can
be executed directly against an in-memory `ProgramDependenceGraph`, without
Neo4j or any external database.

Supported query shape (subset):

  MATCH <pattern> (',' <pattern>)*
  [WHERE <expr>]
  RETURN ('*' | <return_item> (',' <return_item>)*)
  [ORDER BY <expr> (ASC|DESC)? (',' <expr> (ASC|DESC)?)*]
  [LIMIT <int>]

Patterns:
  (n)                            node
  (n:stmt)                       node label (maps to `PDGNode.kind`)
  (n {kind: "stmt"})             node property constraints (equality)
  (a)-[e:data]->(b)              relationship (maps to `PDGEdge.kind`)
  (a)<-[:control]-(b:cond)       reverse relationship
  (a)-[:data]-(b)                undirected relationship

Expressions:
  - literals: strings, ints, floats, true/false/null
  - parameters: $name
  - property access: n.kind, e.label, e.source.node_id
  - comparisons: = != < <= > >= IN
  - boolean ops: AND OR NOT (with parentheses)

Results:
  - Returns a list of records (dicts) mapping return aliases to values.
  - Values may be PDGNode/PDGEdge objects or primitives depending on RETURN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .graph import PDGEdge, PDGNode, ProgramDependenceGraph


class CypherSyntaxError(ValueError):
    pass


class CypherExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    pos: int


_KEYWORDS = {
    "MATCH",
    "WHERE",
    "RETURN",
    "AS",
    "AND",
    "OR",
    "NOT",
    "IN",
    "LIMIT",
    "SKIP",
    "ORDER",
    "BY",
    "ASC",
    "DESC",
    "TRUE",
    "FALSE",
    "NULL",
    "DISTINCT",
}


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_cont(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def tokenize(query: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(query)

    def emit(kind: str, start: int, end: int) -> None:
        tokens.append(Token(kind=kind, text=query[start:end], pos=start))

    while i < n:
        ch = query[i]
        if ch.isspace():
            i += 1
            continue

        # Two-character operators
        if query.startswith("->", i):
            emit("ARROW_R", i, i + 2)
            i += 2
            continue
        if query.startswith("<-", i):
            emit("ARROW_L", i, i + 2)
            i += 2
            continue
        if query.startswith("..", i):
            emit("RANGE", i, i + 2)
            i += 2
            continue
        if (
            query.startswith("<=", i)
            or query.startswith(">=", i)
            or query.startswith("!=", i)
        ):
            emit("OP", i, i + 2)
            i += 2
            continue

        # Single-character punctuation/operators
        if ch in "(),.{}[]:*+-/|":
            emit(ch, i, i + 1)
            i += 1
            continue
        if ch in "=<>":
            emit("OP", i, i + 1)
            i += 1
            continue

        # Parameter
        if ch == "$":
            start = i
            i += 1
            if i >= n or not _is_ident_start(query[i]):
                raise CypherSyntaxError(f"Invalid parameter at position {start}")
            i += 1
            while i < n and _is_ident_cont(query[i]):
                i += 1
            emit("PARAM", start, i)
            continue

        # String literal
        if ch in ("'", '"'):
            quote = ch
            start = i
            i += 1
            out = []
            while i < n:
                c = query[i]
                if c == "\\":
                    if i + 1 >= n:
                        raise CypherSyntaxError(
                            f"Unterminated string at position {start}"
                        )
                    esc = query[i + 1]
                    if esc in ("\\", '"', "'"):
                        out.append(esc)
                    elif esc == "n":
                        out.append("\n")
                    elif esc == "t":
                        out.append("\t")
                    else:
                        out.append(esc)
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    emit("STRING", start, i)
                    break
                out.append(c)
                i += 1
            else:
                raise CypherSyntaxError(f"Unterminated string at position {start}")
            continue

        # Number literal (int/float)
        if ch.isdigit():
            start = i
            i += 1
            while i < n and query[i].isdigit():
                i += 1
            if i < n and query[i] == "." and i + 1 < n and query[i + 1].isdigit():
                i += 1
                while i < n and query[i].isdigit():
                    i += 1
                emit("FLOAT", start, i)
            else:
                emit("INT", start, i)
            continue

        # Identifier/keyword
        if _is_ident_start(ch):
            start = i
            i += 1
            while i < n and _is_ident_cont(query[i]):
                i += 1
            text = query[start:i]
            upper = text.upper()
            if upper in _KEYWORDS:
                emit("KW", start, i)
            else:
                emit("IDENT", start, i)
            continue

        raise CypherSyntaxError(f"Unexpected character {ch!r} at position {i}")

    emit("EOF", n, n)
    return tokens


# --- AST ---


@dataclass(frozen=True)
class NodePattern:
    var: Optional[str]
    labels: Tuple[str, ...]
    props: Tuple[Tuple[str, "Expr"], ...]


@dataclass(frozen=True)
class RelPattern:
    var: Optional[str]
    types: Tuple[str, ...]
    props: Tuple[Tuple[str, "Expr"], ...]
    direction: str  # "->" | "<-" | "--"
    min_hops: int
    max_hops: int
    var_length: bool


@dataclass(frozen=True)
class PatternChain:
    start: NodePattern
    steps: Tuple[Tuple[RelPattern, NodePattern], ...]


@dataclass(frozen=True)
class ReturnItem:
    expr: Optional["Expr"]  # None for '*'
    alias: Optional[str]


@dataclass(frozen=True)
class OrderItem:
    expr: "Expr"
    descending: bool


@dataclass(frozen=True)
class Query:
    patterns: Tuple[PatternChain, ...]
    where: Optional["Expr"]
    distinct: bool
    returns: Tuple[ReturnItem, ...]
    order_by: Tuple[OrderItem, ...]
    limit: Optional[int]
    skip: int


# --- Expressions ---


class Expr:
    pass


@dataclass(frozen=True)
class Literal(Expr):
    value: Any


@dataclass(frozen=True)
class ParamRef(Expr):
    name: str


@dataclass(frozen=True)
class VarRef(Expr):
    name: str


@dataclass(frozen=True)
class Attr(Expr):
    base: Expr
    name: str


@dataclass(frozen=True)
class ListLiteral(Expr):
    items: Tuple[Expr, ...]


@dataclass(frozen=True)
class Unary(Expr):
    op: str  # "NOT" | "-" (optional)
    expr: Expr


@dataclass(frozen=True)
class Binary(Expr):
    op: str  # "AND" | "OR" | "=" | "!=" | "<" | "<=" | ">" | ">=" | "IN"
    left: Expr
    right: Expr


@dataclass(frozen=True)
class FuncCall(Expr):
    name: str
    args: Tuple[Expr, ...]


# --- Parser ---


class _Parser:
    __slots__ = ("tokens", "i", "query")

    def __init__(self, query: str):
        self.query = query
        self.tokens = tokenize(query)
        self.i = 0

    def peek(self) -> Token:
        return self.tokens[self.i]

    def pop(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def accept(self, kind: str, text_upper: Optional[str] = None) -> Optional[Token]:
        tok = self.peek()
        if tok.kind != kind:
            return None
        if text_upper is not None:
            if tok.text.upper() != text_upper:
                return None
        return self.pop()

    def expect(self, kind: str, text_upper: Optional[str] = None) -> Token:
        tok = self.peek()
        if tok.kind != kind or (
            text_upper is not None and tok.text.upper() != text_upper
        ):
            want = text_upper if text_upper is not None else kind
            raise CypherSyntaxError(f"Expected {want} at position {tok.pos}")
        return self.pop()

    def parse(self) -> Query:
        self.expect("KW", "MATCH")
        patterns = [self.parse_pattern_chain()]
        while self.accept(","):
            patterns.append(self.parse_pattern_chain())

        where_expr = None
        if self.accept("KW", "WHERE"):
            where_expr = self.parse_expr()

        self.expect("KW", "RETURN")
        distinct = bool(self.accept("KW", "DISTINCT"))
        returns = self.parse_return_list()

        order_by: List[OrderItem] = []
        if self.accept("KW", "ORDER"):
            self.expect("KW", "BY")
            order_by.append(self.parse_order_item())
            while self.accept(","):
                order_by.append(self.parse_order_item())

        skip = 0
        if self.accept("KW", "SKIP"):
            tok = self.expect("INT")
            skip = int(tok.text)

        limit = None
        if self.accept("KW", "LIMIT"):
            tok = self.expect("INT")
            limit = int(tok.text)

        self.expect("EOF")
        return Query(
            patterns=tuple(patterns),
            where=where_expr,
            distinct=distinct,
            returns=tuple(returns),
            order_by=tuple(order_by),
            limit=limit,
            skip=skip,
        )

    def parse_order_item(self) -> OrderItem:
        expr = self.parse_expr()
        descending = False
        if self.accept("KW", "ASC"):
            descending = False
        elif self.accept("KW", "DESC"):
            descending = True
        return OrderItem(expr=expr, descending=descending)

    def parse_return_list(self) -> List[ReturnItem]:
        if self.accept("*"):
            return [ReturnItem(expr=None, alias=None)]

        items: List[ReturnItem] = [self.parse_return_item()]
        while self.accept(","):
            items.append(self.parse_return_item())
        return items

    def parse_return_item(self) -> ReturnItem:
        expr = self.parse_expr()
        alias = None
        if self.accept("KW", "AS"):
            alias = self.expect("IDENT").text
        return ReturnItem(expr=expr, alias=alias)

    def parse_pattern_chain(self) -> PatternChain:
        start = self.parse_node_pattern()
        steps: List[Tuple[RelPattern, NodePattern]] = []
        while True:
            tok = self.peek()
            if tok.kind in ("-", "ARROW_L"):
                rel = self.parse_rel_pattern()
                nxt = self.parse_node_pattern()
                steps.append((rel, nxt))
                continue
            break
        return PatternChain(start=start, steps=tuple(steps))

    def parse_node_pattern(self) -> NodePattern:
        self.expect("(")
        var = None
        labels: List[str] = []
        props: List[Tuple[str, Expr]] = []

        if self.peek().kind == "IDENT":
            var = self.pop().text

        while self.accept(":"):
            labels.append(self.expect("IDENT").text)

        if self.accept("{"):
            if not self.accept("}"):
                while True:
                    key_tok = self.peek()
                    if key_tok.kind not in ("IDENT", "STRING"):
                        raise CypherSyntaxError(
                            f"Expected property key at position {key_tok.pos}"
                        )
                    key = self.pop().text
                    if key_tok.kind == "STRING":
                        key = key[1:-1]
                    self.expect(":")
                    value = self.parse_expr()
                    props.append((key, value))
                    if self.accept("}"):
                        break
                    self.expect(",")

        self.expect(")")
        return NodePattern(var=var, labels=tuple(labels), props=tuple(props))

    def parse_rel_pattern(self) -> RelPattern:
        direction_left = False
        direction_right = False

        if self.accept("ARROW_L"):
            direction_left = True
        else:
            self.expect("-")

        var = None
        types: List[str] = []
        props: List[Tuple[str, Expr]] = []
        min_hops = 1
        max_hops = 1
        var_length = False

        if self.accept("["):
            if self.peek().kind == "IDENT":
                var = self.pop().text
            if self.accept(":"):
                # Allow multiple types separated by |
                types.append(self.expect("IDENT").text)
                while self.accept("|"):
                    types.append(self.expect("IDENT").text)

            if self.accept("*"):
                # [:KIND*] or [:KIND*2] or [:KIND*1..3] or [:KIND*..3]
                var_length = True
                if self.peek().kind == "INT":
                    min_hops = int(self.pop().text)
                    max_hops = min_hops
                elif self.accept("RANGE"):
                    min_hops = 1
                    max_hops = int(self.expect("INT").text)

                if self.accept("RANGE"):
                    # *N..M
                    max_hops = int(self.expect("INT").text)
                    if max_hops < min_hops:
                        raise CypherSyntaxError("Invalid relationship length range")

            if self.accept("{"):
                if not self.accept("}"):
                    while True:
                        key_tok = self.peek()
                        if key_tok.kind not in ("IDENT", "STRING"):
                            raise CypherSyntaxError(
                                f"Expected property key at position {key_tok.pos}"
                            )
                        key = self.pop().text
                        if key_tok.kind == "STRING":
                            key = key[1:-1]
                        self.expect(":")
                        value = self.parse_expr()
                        props.append((key, value))
                        if self.accept("}"):
                            break
                        self.expect(",")

            self.expect("]")

        if self.accept("ARROW_R"):
            direction_right = True
        else:
            self.expect("-")

        if direction_left and direction_right:
            raise CypherSyntaxError(
                "Relationship cannot be both left and right directed"
            )

        direction = "--"
        if direction_left:
            direction = "<-"
        elif direction_right:
            direction = "->"

        return RelPattern(
            var=var,
            types=tuple(types),
            props=tuple(props),
            direction=direction,
            min_hops=min_hops,
            max_hops=max_hops,
            var_length=var_length,
        )

    # --- Expression parsing (precedence climbing) ---

    def parse_expr(self) -> Expr:
        return self.parse_or()

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.peek().kind == "KW" and self.peek().text.upper() == "OR":
            self.pop()
            right = self.parse_and()
            left = Binary("OR", left, right)
        return left

    def parse_and(self) -> Expr:
        left = self.parse_not()
        while self.peek().kind == "KW" and self.peek().text.upper() == "AND":
            self.pop()
            right = self.parse_not()
            left = Binary("AND", left, right)
        return left

    def parse_not(self) -> Expr:
        if self.peek().kind == "KW" and self.peek().text.upper() == "NOT":
            self.pop()
            return Unary("NOT", self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Expr:
        left = self.parse_term()
        tok = self.peek()
        if tok.kind == "OP":
            op = tok.text
            if op in ("=", "!=", "<", "<=", ">", ">="):
                self.pop()
                right = self.parse_term()
                return Binary(op, left, right)
        if tok.kind == "KW" and tok.text.upper() == "IN":
            self.pop()
            right = self.parse_term()
            return Binary("IN", left, right)
        return left

    def parse_term(self) -> Expr:
        # Parenthesized expression
        if self.accept("("):
            e = self.parse_expr()
            self.expect(")")
            return e

        # Special literal used by aggregations like count(*)
        if self.accept("*"):
            return Literal("*")

        tok = self.peek()

        if tok.kind == "PARAM":
            t = self.pop().text
            return ParamRef(t[1:])

        if tok.kind == "KW":
            kw = tok.text.upper()
            if kw == "TRUE":
                self.pop()
                return Literal(True)
            if kw == "FALSE":
                self.pop()
                return Literal(False)
            if kw == "NULL":
                self.pop()
                return Literal(None)

        if tok.kind == "INT":
            self.pop()
            return Literal(int(tok.text))
        if tok.kind == "FLOAT":
            self.pop()
            return Literal(float(tok.text))
        if tok.kind == "STRING":
            self.pop()
            return Literal(tok.text[1:-1])

        # List literal
        if self.accept("["):
            items: List[Expr] = []
            if not self.accept("]"):
                while True:
                    items.append(self.parse_expr())
                    if self.accept("]"):
                        break
                    self.expect(",")
            return ListLiteral(tuple(items))

        # identifier: var or function call
        if tok.kind == "IDENT":
            name = self.pop().text
            expr: Expr = VarRef(name)
            if self.accept("("):
                args: List[Expr] = []
                if not self.accept(")"):
                    while True:
                        args.append(self.parse_expr())
                        if self.accept(")"):
                            break
                        self.expect(",")
                expr = FuncCall(name=name, args=tuple(args))

            # attribute chain
            while self.accept("."):
                attr = self.expect("IDENT").text
                expr = Attr(expr, attr)
            return expr

        raise CypherSyntaxError(
            f"Unexpected token {tok.kind}:{tok.text!r} at position {tok.pos}"
        )


def parse(query: str) -> Query:
    return _Parser(query).parse()


# --- Execution ---


def _get_attr(obj: Any, name: str) -> Any:
    if isinstance(obj, PDGNode):
        if name == "node_id":
            return obj.node_id
        if name == "kind":
            return obj.kind
        if name == "label":
            return obj.label
        if name == "cfg_type":
            return type(obj.cfg_node).__name__ if obj.cfg_node is not None else None
        if name == "ast_type":
            return type(obj.ast_node).__name__ if obj.ast_node is not None else None
        if name == "cfg_node":
            return obj.cfg_node
        if name == "ast_node":
            return obj.ast_node
        raise CypherExecutionError(f"Unknown PDGNode property: {name}")
    if isinstance(obj, PDGEdge):
        if name == "kind":
            return obj.kind
        if name == "label":
            return obj.label
        if name == "source":
            return obj.source
        if name == "target":
            return obj.target
        if name == "source_id":
            return obj.source.node_id
        if name == "target_id":
            return obj.target.node_id
        raise CypherExecutionError(f"Unknown PDGEdge property: {name}")

    # Allow attribute access on dict-like results
    if isinstance(obj, dict) and name in obj:
        return obj[name]

    raise CypherExecutionError(
        f"Cannot access property {name!r} on {type(obj).__name__}"
    )


def _eval_expr(
    expr: Expr, row: Dict[str, Any], params: Optional[Dict[str, Any]]
) -> Any:
    if isinstance(expr, Literal):
        return expr.value
    if isinstance(expr, ParamRef):
        if params is None or expr.name not in params:
            raise CypherExecutionError(f"Missing parameter: ${expr.name}")
        return params[expr.name]
    if isinstance(expr, VarRef):
        if expr.name not in row:
            raise CypherExecutionError(f"Unbound variable: {expr.name}")
        return row[expr.name]
    if isinstance(expr, Attr):
        base = _eval_expr(expr.base, row, params)
        return _get_attr(base, expr.name)
    if isinstance(expr, ListLiteral):
        return [_eval_expr(it, row, params) for it in expr.items]
    if isinstance(expr, Unary):
        v = _eval_expr(expr.expr, row, params)
        if expr.op == "NOT":
            return not bool(v)
        if expr.op == "-":
            return -v
        raise CypherExecutionError(f"Unsupported unary op: {expr.op}")
    if isinstance(expr, Binary):
        if expr.op == "AND":
            return bool(_eval_expr(expr.left, row, params)) and bool(
                _eval_expr(expr.right, row, params)
            )
        if expr.op == "OR":
            return bool(_eval_expr(expr.left, row, params)) or bool(
                _eval_expr(expr.right, row, params)
            )

        left = _eval_expr(expr.left, row, params)
        right = _eval_expr(expr.right, row, params)
        if expr.op == "=":
            return left == right
        if expr.op == "!=":
            return left != right
        if expr.op == "<":
            return left < right
        if expr.op == "<=":
            return left <= right
        if expr.op == ">":
            return left > right
        if expr.op == ">=":
            return left >= right
        if expr.op == "IN":
            return left in right
        raise CypherExecutionError(f"Unsupported binary op: {expr.op}")
    if isinstance(expr, FuncCall):
        fname = expr.name.lower()
        args = [_eval_expr(a, row, params) for a in expr.args]
        if fname == "id" and len(args) == 1:
            a = args[0]
            if isinstance(a, PDGNode):
                return a.node_id
            if isinstance(a, PDGEdge):
                return (a.source.node_id, a.target.node_id, a.kind, a.label)
            return a
        if fname == "type" and len(args) == 1:
            return type(args[0]).__name__
        raise CypherExecutionError(
            f"Unsupported function: {expr.name}({len(args)} args)"
        )
    raise CypherExecutionError(f"Unsupported expression node: {type(expr).__name__}")


def _node_matches(
    pdg_node: PDGNode,
    pat: NodePattern,
    row: Dict[str, Any],
    params: Optional[Dict[str, Any]],
) -> bool:
    if pat.labels:
        # Labels map to PDGNode.kind
        if pdg_node.kind not in pat.labels:
            return False
    for k, vexpr in pat.props:
        expected = _eval_expr(vexpr, row, params)
        actual = _get_attr(pdg_node, k)
        if actual != expected:
            return False
    return True


def _edge_matches(
    edge: PDGEdge,
    pat: RelPattern,
    row: Dict[str, Any],
    params: Optional[Dict[str, Any]],
) -> bool:
    if pat.types:
        if edge.kind not in pat.types:
            return False
    for k, vexpr in pat.props:
        expected = _eval_expr(vexpr, row, params)
        actual = _get_attr(edge, k)
        if actual != expected:
            return False
    return True


def _bind_var(
    row: Dict[str, Any], name: Optional[str], value: Any
) -> Optional[Dict[str, Any]]:
    if name is None:
        return row
    if name in row:
        return row if row[name] == value else None
    new = dict(row)
    new[name] = value
    return new


def _iter_edges_for_direction(
    node: PDGNode, direction: str
) -> Iterator[Tuple[PDGEdge, PDGNode]]:
    if direction == "->":
        for e in node.edges_out:
            yield e, e.target
    elif direction == "<-":
        for e in node.edges_in:
            yield e, e.source
    else:  # "--"
        for e in node.edges_out:
            yield e, e.target
        for e in node.edges_in:
            yield e, e.source


def _iter_paths(
    start: PDGNode,
    rel_pat: RelPattern,
    *,
    bound_value: Optional[Any],
    row: Dict[str, Any],
    params: Optional[Dict[str, Any]],
) -> Iterator[Tuple[Tuple[PDGEdge, ...], PDGNode]]:
    """
    Iterate (edge_sequence, end_node) pairs that satisfy a relationship pattern.

    If the relationship pattern uses variable length (`*`), the relationship
    variable binds to a tuple of edges; otherwise it binds to a single edge.
    """
    if rel_pat.min_hops < 1 or rel_pat.max_hops < rel_pat.min_hops:
        return

    # If relationship variable is already bound, validate it and only allow that path.
    if bound_value is not None:
        if not rel_pat.var_length:
            if not isinstance(bound_value, PDGEdge):
                return
            if not _edge_matches(bound_value, rel_pat, row, params):
                return
            # Verify direction and determine neighbor.
            if rel_pat.direction == "->":
                if bound_value.source is not start:
                    return
                yield (bound_value,), bound_value.target
                return
            if rel_pat.direction == "<-":
                if bound_value.target is not start:
                    return
                yield (bound_value,), bound_value.source
                return
            # undirected
            if bound_value.source is start:
                yield (bound_value,), bound_value.target
            elif bound_value.target is start:
                yield (bound_value,), bound_value.source
            return

        # Variable-length binding: require a tuple/list of edges.
        if not isinstance(bound_value, (list, tuple)):
            return
        edges = tuple(bound_value)
        if not (rel_pat.min_hops <= len(edges) <= rel_pat.max_hops):
            return
        cur = start
        for e in edges:
            if not isinstance(e, PDGEdge):
                return
            if not _edge_matches(e, rel_pat, row, params):
                return
            if rel_pat.direction == "->":
                if e.source is not cur:
                    return
                cur = e.target
            elif rel_pat.direction == "<-":
                if e.target is not cur:
                    return
                cur = e.source
            else:
                if e.source is cur:
                    cur = e.target
                elif e.target is cur:
                    cur = e.source
                else:
                    return
        yield edges, cur
        return

    # Unbound relationship variable: explore.
    # DFS bounded by max_hops; avoid pathological blowups by tracking (node, depth).
    stack: List[Tuple[PDGNode, Tuple[PDGEdge, ...]]] = [(start, ())]
    seen_states: set[Tuple[int, int]] = set()

    while stack:
        cur, path = stack.pop()
        depth = len(path)
        state = (cur.node_id, depth)
        if state in seen_states:
            continue
        seen_states.add(state)

        if depth >= rel_pat.max_hops:
            continue

        for edge, nxt in _iter_edges_for_direction(cur, rel_pat.direction):
            if not _edge_matches(edge, rel_pat, row, params):
                continue
            new_path = path + (edge,)
            new_depth = depth + 1
            if rel_pat.min_hops <= new_depth <= rel_pat.max_hops:
                yield new_path, nxt
            if new_depth < rel_pat.max_hops:
                stack.append((nxt, new_path))


def _match_chain(
    pdg: ProgramDependenceGraph,
    chain: PatternChain,
    rows: List[Dict[str, Any]],
    params: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    def candidates_for_node(pat: NodePattern, row: Dict[str, Any]) -> List[PDGNode]:
        if pat.var is not None and pat.var in row:
            v = row[pat.var]
            if not isinstance(v, PDGNode):
                return []
            return [v] if _node_matches(v, pat, row, params) else []
        return [n for n in pdg.nodes if _node_matches(n, pat, row, params)]

    out_rows: List[Dict[str, Any]] = []
    for row in rows:
        for start_node in candidates_for_node(chain.start, row):
            row1 = _bind_var(row, chain.start.var, start_node)
            if row1 is None:
                continue

            partial: List[Tuple[PDGNode, Dict[str, Any]]] = [(start_node, row1)]
            for rel_pat, node_pat in chain.steps:
                next_partial: List[Tuple[PDGNode, Dict[str, Any]]] = []
                for cur_node, cur_row in partial:
                    bound_rel = None
                    if rel_pat.var is not None and rel_pat.var in cur_row:
                        bound_rel = cur_row[rel_pat.var]

                    for edge_seq, neighbor in _iter_paths(
                        cur_node,
                        rel_pat,
                        bound_value=bound_rel,
                        row=cur_row,
                        params=params,
                    ):
                        if not _node_matches(neighbor, node_pat, cur_row, params):
                            continue

                        rel_value: Any = edge_seq if rel_pat.var_length else edge_seq[0]

                        r2 = _bind_var(cur_row, rel_pat.var, rel_value)
                        if r2 is None:
                            continue
                        r3 = _bind_var(r2, node_pat.var, neighbor)
                        if r3 is None:
                            continue
                        next_partial.append((neighbor, r3))
                partial = next_partial
                if not partial:
                    break

            for _, final_row in partial:
                out_rows.append(final_row)

    return out_rows


def execute(
    pdg: ProgramDependenceGraph,
    query: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    ast = parse(query)

    rows: List[Dict[str, Any]] = [dict()]
    for chain in ast.patterns:
        rows = _match_chain(pdg, chain, rows, params)

    if ast.where is not None:
        filtered: List[Dict[str, Any]] = []
        for r in rows:
            if bool(_eval_expr(ast.where, r, params)):
                filtered.append(r)
        rows = filtered

    if ast.order_by:
        alias_expr: Dict[str, Expr] = {}
        for item in ast.returns:
            if item.expr is None:
                continue
            if item.alias is not None:
                alias_expr[item.alias] = item.expr

        def eval_for_order(expr: Expr, row: Dict[str, Any]) -> Any:
            # Allow ORDER BY <return-alias> (Cypher-like behavior)
            if (
                isinstance(expr, VarRef)
                and expr.name not in row
                and expr.name in alias_expr
            ):
                return _eval_expr(alias_expr[expr.name], row, params)
            return _eval_expr(expr, row, params)

        def key(row: Dict[str, Any]):
            return tuple(eval_for_order(it.expr, row) for it in ast.order_by)

        rows.sort(key=key)
        # Apply descending per item by stable sorts from last to first.
        for idx in range(len(ast.order_by) - 1, -1, -1):
            if ast.order_by[idx].descending:
                rows.sort(
                    key=lambda r, i=idx: eval_for_order(ast.order_by[i].expr, r),
                    reverse=True,
                )

    if ast.returns and ast.returns[0].expr is None:
        # RETURN *
        result = [dict(r) for r in rows]
    else:

        def is_aggregate(expr: Expr) -> bool:
            return isinstance(expr, FuncCall) and expr.name.lower() in (
                "count",
                "collect",
            )

        has_agg = any(
            item.expr is not None and is_aggregate(item.expr) for item in ast.returns
        )
        has_non_agg = any(
            item.expr is not None and not is_aggregate(item.expr)
            for item in ast.returns
        )
        if has_agg and has_non_agg:
            raise CypherExecutionError(
                "Mixing aggregations and non-aggregated RETURN items is not supported (use separate queries)"
            )

        if has_agg:
            record: Dict[str, Any] = {}
            for item in ast.returns:
                assert item.expr is not None
                expr = item.expr
                assert isinstance(expr, FuncCall)
                fname = expr.name.lower()

                key = item.alias or "expr"
                if fname == "count":
                    if (
                        len(expr.args) == 1
                        and isinstance(expr.args[0], Literal)
                        and expr.args[0].value == "*"
                    ):
                        record[key] = len(rows)
                    elif len(expr.args) == 1:
                        cnt = 0
                        for r in rows:
                            v = _eval_expr(expr.args[0], r, params)
                            if v is not None:
                                cnt += 1
                        record[key] = cnt
                    else:
                        raise CypherExecutionError("count() expects 1 argument")
                elif fname == "collect":
                    if len(expr.args) != 1:
                        raise CypherExecutionError("collect() expects 1 argument")
                    record[key] = [_eval_expr(expr.args[0], r, params) for r in rows]
                else:
                    raise CypherExecutionError(f"Unsupported aggregation: {expr.name}")
            result = [record]
        else:
            result = []
            for r in rows:
                record = {}
                for item in ast.returns:
                    assert item.expr is not None
                    value = _eval_expr(item.expr, r, params)
                    key = item.alias
                    if key is None:
                        if isinstance(item.expr, VarRef):
                            key = item.expr.name
                        elif isinstance(item.expr, Attr) and isinstance(
                            item.expr.base, VarRef
                        ):
                            key = f"{item.expr.base.name}.{item.expr.name}"
                        else:
                            key = "expr"
                    record[key] = value
                result.append(record)

    if ast.distinct:
        seen = set()
        uniq: List[Dict[str, Any]] = []
        for rec in result:
            key = tuple(sorted((k, repr(v)) for k, v in rec.items()))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(rec)
        result = uniq

    if ast.skip:
        result = result[ast.skip :]
    if ast.limit is not None:
        result = result[: ast.limit]

    return result
