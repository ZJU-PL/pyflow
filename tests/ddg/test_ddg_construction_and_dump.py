"""Focused regression tests for DDG construction and dumping."""

import json
import os
import tempfile
import unittest

from pyflow.analysis.dataflowIR import graph as df
from pyflow.analysis.ddg import construct_ddg
from pyflow.analysis.ddg.dump import DDGDumper
from pyflow.analysis.ddg.graph import DataDependenceGraph


class FakeSlot(df.SlotNode):
    __slots__ = ("name", "object", "defn", "_users")

    def __init__(self, name, object=None):
        super().__init__(None)
        self.name = name
        self.object = object
        self.defn = None
        self._users = []

    def add_user(self, op):
        self._users.append(op)
        return self

    def forward(self):
        return tuple(self._users)

    def reverse(self):
        if self.defn is None:
            return ()
        return (self.defn,)

    def __repr__(self):
        return "slot(%s)" % self.name


class FakeOp(df.OpNode):
    __slots__ = ("name", "_forward", "heapReads", "heapModifies", "heapPsedoReads")

    def __init__(
        self,
        name,
        heap_reads=None,
        heap_modifies=None,
        heap_pseudo_reads=None,
    ):
        super().__init__(None)
        self.name = name
        self._forward = []
        self.heapReads = heap_reads or {}
        self.heapModifies = heap_modifies or {}
        self.heapPsedoReads = heap_pseudo_reads or {}

    def connect(self, *nodes):
        self._forward.extend(nodes)
        return self

    def forward(self):
        return tuple(self._forward)

    def reverse(self):
        return ()

    def __repr__(self):
        return "op(%s)" % self.name


class FakeDataflow(object):
    __slots__ = ("entry", "exit", "existing", "null", "entryPredicate")

    def __init__(self, entry, exit=None):
        self.entry = entry
        self.exit = exit
        self.existing = {}
        self.null = FakeSlot("null")
        self.entryPredicate = None


class TestDDGConstructionRegression(unittest.TestCase):
    def test_constructed_ddg_connects_slot_nodes(self):
        entry = FakeOp("entry")
        producer = FakeOp("producer")
        consumer = FakeOp("consumer")
        value = FakeSlot("value")
        value.defn = producer
        value.add_user(consumer)

        entry.connect(producer)
        producer.connect(value)

        ddg = construct_ddg(FakeDataflow(entry))
        slot_node = ddg.slot_node_map[value]

        self.assertTrue(
            any(
                edge.source.ir_node is producer
                and edge.target is slot_node
                and edge.kind == "def-use"
                for edge in slot_node.edges_in
            )
        )
        self.assertTrue(
            any(
                edge.source is slot_node
                and edge.target.ir_node is consumer
                and edge.kind == "def-use"
                for edge in slot_node.edges_out
            )
        )

    def test_memory_dependencies_include_war(self):
        field = FakeSlot("field")
        entry = FakeOp("entry")
        reader = FakeOp("reader", heap_reads={"field": field})
        writer = FakeOp("writer", heap_modifies={"field": field})

        entry.connect(reader)
        reader.connect(writer)

        ddg = construct_ddg(FakeDataflow(entry))
        edges = [
            edge
            for edge in ddg.all_edges()
            if edge.kind == "memory" and edge.label == "WAR"
        ]

        self.assertEqual(len(edges), 1)
        self.assertIs(edges[0].source.ir_node, reader)
        self.assertIs(edges[0].target.ir_node, writer)

    def test_memory_dependencies_use_topological_op_order(self):
        field = FakeSlot("field")
        entry = FakeOp("entry")
        writer = FakeOp("writer", heap_modifies={"field": field})
        bypass = FakeOp("bypass")
        consumer = FakeOp("consumer", heap_reads={"field": field})

        # DFS discovery from entry visits bypass -> consumer before writer.
        entry.connect(writer, bypass)
        writer.connect(consumer)
        bypass.connect(consumer)

        ddg = construct_ddg(FakeDataflow(entry))
        edges = [
            edge
            for edge in ddg.all_edges()
            if edge.kind == "memory" and edge.label == "RAW"
        ]

        self.assertEqual(len(edges), 1)
        self.assertIs(edges[0].source.ir_node, writer)
        self.assertIs(edges[0].target.ir_node, consumer)

    def test_memory_dependencies_distinguish_same_field_name_on_different_objects(self):
        entry = FakeOp("entry")
        write_a = FakeOp("write_a", heap_modifies={"x": FakeSlot("x", object="a")})
        read_b = FakeOp("read_b", heap_reads={"x": FakeSlot("x", object="b")})

        entry.connect(write_a)
        write_a.connect(read_b)

        ddg = construct_ddg(FakeDataflow(entry))
        edges = [edge for edge in ddg.all_edges() if edge.kind == "memory"]

        self.assertEqual(edges, [])


class TestDDGDumpRegression(unittest.TestCase):
    def test_dump_preserves_edge_labels_and_node_identity(self):
        ddg = DataDependenceGraph()
        producer = ddg.get_or_create_op_node("producer")
        slot = ddg.get_or_create_slot_node("slot_x")
        consumer = ddg.get_or_create_op_node("consumer")

        producer.add_edge_to(slot, "def-use", "slot_x")
        slot.add_edge_to(consumer, "def-use", "slot_x")
        ddg.add_mem_dep(producer, consumer, "RAW")

        dumper = DDGDumper(ddg)
        with tempfile.TemporaryDirectory() as tmpdir:
            text_path = os.path.join(tmpdir, "ddg.txt")
            json_path = os.path.join(tmpdir, "ddg.json")
            dot_path = os.path.join(tmpdir, "ddg.dot")

            dumper.dump_text(text_path)
            dumper.dump_json(json_path)
            dumper.dump_dot(dot_path)

            with open(text_path) as f:
                text_output = f.read()
            self.assertIn("slot_x", text_output)
            self.assertIn("RAW", text_output)
            self.assertIn("'producer'", text_output)

            with open(json_path) as f:
                json_output = json.load(f)
            self.assertIn("ir", json_output["nodes"][0])
            self.assertTrue(any(edge["label"] == "slot_x" for edge in json_output["edges"]))
            self.assertTrue(any(edge["label"] == "RAW" for edge in json_output["edges"]))

            with open(dot_path) as f:
                dot_output = f.read()
            self.assertIn("def-use:slot_x", dot_output)
            self.assertIn("'producer'", dot_output)


if __name__ == "__main__":
    unittest.main()
