"""Flatten an unflattened GIR tree into Lian-compatible rows.

Replicates ``lian.lang.lang_analysis.GIRProcessing``:

* every statement becomes a row ``{operation, stmt_id, parent_stmt_id, ...}``;
* nested block bodies become ``block_start``/``block_end`` rows whose id is
  referenced from the owning statement row;
* an ``original_stmt`` link is stamped on a preceding ``variable_decl`` row
  whenever the current row is an ``assign_stmt``/``call_stmt``;
* non-block list fields are stringified exactly like Lian does
  (``str(myvalue)``) so positional/named argument lists round-trip.

``assign_id`` starts from an external counter so ids stay unique when
flattening multiple units in one analysis run.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

OPTIONAL_CLAUSE_BODY_KEYS = frozenset(
    {"else_body", "elsebody", "catch_body", "final_body", "finally_body"}
)


class GirFlattener:
    def __init__(self, start_id: int = 1) -> None:
        # ids start at 1 so that parent_stmt_id == 0 uniquely means "module
        # top-level"; the first statement's child blocks would otherwise
        # share parent id 0 and get mistaken for top-level statements.
        self.node_id = start_id

    def assign_id(self) -> int:
        previous = self.node_id
        self.node_id += 1
        return previous

    def flatten(self, stmts: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
        if not self.is_gir_format(stmts):
            raise ValueError("The input format of GLang IR is not correct.")
        flattened_nodes = self._flatten_gir(stmts)
        return (self.node_id, flattened_nodes)

    @staticmethod
    def is_gir_format(stmts: List[Any]) -> bool:
        return bool(
            stmts
            and isinstance(stmts, list)
            and len(stmts) > 0
            and stmts[0]
            and isinstance(stmts[0], dict)
        )

    def _flatten_gir(self, stmts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flattened_nodes: List[Dict[str, Any]] = []
        last_node: Dict[str, Any] = {}
        for stmt in stmts:
            last_node = self.flatten_stmt(stmt, last_node, flattened_nodes)
        return flattened_nodes

    def flatten_stmt(
        self,
        stmt: Dict[str, Any],
        last_node: Dict[str, Any],
        dataframe: List[Dict[str, Any]],
        parent_stmt_id: int = 0,
    ) -> Dict[str, Any]:
        if not isinstance(stmt, dict):
            raise ValueError(
                "[Input format error] The input node should be a dictionary: "
                + str(stmt)
            )

        flattened_node: Dict[str, Any] = {}
        dataframe.append(flattened_node)

        flattened_node["operation"] = next(iter(stmt.keys()))
        stmt_content = stmt[flattened_node["operation"]]

        self.init_stmt_id(flattened_node, parent_stmt_id)

        if (
            flattened_node["operation"] in ("assign_stmt", "call_stmt")
            and "operation" in last_node
            and last_node["operation"] == "variable_decl"
        ):
            last_node["original_stmt"] = flattened_node["stmt_id"]

        if not isinstance(stmt_content, dict):
            return flattened_node

        for mykey, myvalue in stmt_content.items():
            if isinstance(myvalue, list):
                if not self.is_gir_format(myvalue):
                    if "body" in mykey and mykey not in OPTIONAL_CLAUSE_BODY_KEYS:
                        block_id = self.flatten_block(
                            myvalue, flattened_node["stmt_id"], dataframe
                        )
                        flattened_node[mykey] = block_id
                        continue
                    if len(myvalue) == 0:
                        flattened_node[mykey] = None
                    else:
                        flattened_node[mykey] = str(myvalue)
                else:
                    block_id = self.flatten_block(
                        myvalue, flattened_node["stmt_id"], dataframe
                    )
                    flattened_node[mykey] = block_id
            elif isinstance(myvalue, dict):
                raise ValueError(
                    "[Input format error] Dictionary is not allowed: " + str(myvalue)
                )
            else:
                flattened_node[mykey] = myvalue

        return flattened_node

    def flatten_block(
        self,
        block: List[Dict[str, Any]],
        parent_stmt_id: int,
        dataframe: List[Dict[str, Any]],
    ) -> int:
        block_id = self.assign_id()
        dataframe.append(
            {
                "operation": "block_start",
                "stmt_id": block_id,
                "parent_stmt_id": parent_stmt_id,
            }
        )
        last_node: Dict[str, Any] = {}
        for child in block:
            last_node = self.flatten_stmt(child, last_node, dataframe, block_id)
        dataframe.append(
            {
                "operation": "block_end",
                "stmt_id": block_id,
                "parent_stmt_id": parent_stmt_id,
            }
        )
        return block_id

    def init_stmt_id(self, stmt: Dict[str, Any], parent_stmt_id: int) -> None:
        stmt["parent_stmt_id"] = parent_stmt_id
        stmt["stmt_id"] = self.assign_id()
