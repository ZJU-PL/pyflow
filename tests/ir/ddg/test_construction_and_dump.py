"""Focused regression tests for DDG construction and dumping."""

import json
import os
import tempfile
import unittest

from pyflow.application.context import CompilerContext
from pyflow.frontend.extractor import Extractor
from pyflow.ir.core.source import syntax_source_span
from pyflow.ir.dataflow import convert
from pyflow.ir.dataflow import graph as df
from pyflow.ir.ddg import (
    construct_ddg,
    DDGConstructor,
    MalformedForwardingCycleError,
)
from pyflow.ir.ddg.construction import _memory_slot_key
from pyflow.ir.ddg.dump import DDGDumper
from pyflow.ir.ddg.graph import DataDependenceGraph


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


class ForwardedValue:
    def __init__(self):
        self.forward = self

    def getForward(self):
        return self.forward


class TestForwardingDiagnostics(unittest.TestCase):
    def test_malformed_forwarding_cycle_is_diagnosed(self):
        left = ForwardedValue()
        right = ForwardedValue()
        left.forward = right
        right.forward = left

        with self.assertRaises(MalformedForwardingCycleError):
            _memory_slot_key(left)


class ForwardingFieldName(object):
    def __init__(self, name, forward=None):
        self.slotName = name
        self.forward = forward

    def getForward(self):
        return self.forward.getForward() if self.forward is not None else self


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
        edges = [edge for edge in ddg.all_edges() if edge.kind == "memory" and edge.label == "WAR"]

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
        edges = [edge for edge in ddg.all_edges() if edge.kind == "memory" and edge.label == "RAW"]

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

    def test_memory_dependencies_canonicalize_forwarded_field_names(self):
        canonical = ForwardingFieldName("field")
        alias = ForwardingFieldName("field", canonical)
        entry = FakeOp("entry")
        writer = FakeOp("writer", heap_modifies={"field": FakeSlot(alias)})
        reader = FakeOp("reader", heap_reads={"field": FakeSlot(canonical)})
        entry.connect(writer)
        writer.connect(reader)

        ddg = construct_ddg(FakeDataflow(entry))
        memory = [edge for edge in ddg.all_edges() if edge.kind == "memory"]

        self.assertEqual(len(memory), 1)
        self.assertEqual(memory[0].label, "RAW")
        self.assertIs(memory[0].location, canonical)

    def test_memory_dependencies_keep_all_reaching_branch_writes(self):
        field = FakeSlot("field")
        entry = FakeOp("entry")
        write_a = FakeOp("write_a", heap_modifies={"field": field})
        write_b = FakeOp("write_b", heap_modifies={"field": field})
        join_read = FakeOp("join_read", heap_reads={"field": field})

        entry.connect(write_a, write_b)
        write_a.connect(join_read)
        write_b.connect(join_read)

        ddg = construct_ddg(FakeDataflow(entry))
        memory = {
            (edge.source.ir_node.name, edge.target.ir_node.name, edge.label)
            for edge in ddg.all_edges()
            if edge.kind == "memory"
        }

        self.assertEqual(
            memory,
            {
                ("write_a", "join_read", "RAW"),
                ("write_b", "join_read", "RAW"),
            },
        )

    def test_memory_dependencies_reach_a_loop_fixed_point(self):
        field = FakeSlot("field")
        entry = FakeOp("entry")
        write_a = FakeOp("write_a", heap_modifies={"field": field})
        read = FakeOp("read", heap_reads={"field": field})
        write_b = FakeOp("write_b", heap_modifies={"field": field})

        entry.connect(write_a)
        write_a.connect(read)
        read.connect(write_b)
        write_b.connect(write_a)

        ddg = construct_ddg(FakeDataflow(entry))
        memory = {
            (edge.source.ir_node.name, edge.target.ir_node.name, edge.label)
            for edge in ddg.all_edges()
            if edge.kind == "memory"
        }

        self.assertEqual(
            memory,
            {
                ("write_a", "read", "RAW"),
                ("read", "write_b", "WAR"),
                ("write_a", "write_b", "WAW"),
                ("write_b", "write_a", "WAW"),
            },
        )

    def test_indexing_traverses_existing_value_roots(self):
        entry = FakeOp("entry")
        external = FakeSlot("external")
        producer = FakeOp("producer")
        produced = FakeSlot("produced")
        consumer = FakeOp("consumer")
        external.add_user(producer)
        producer.connect(produced)
        produced.defn = producer
        produced.add_user(consumer)

        dataflow = FakeDataflow(entry)
        dataflow.existing["external"] = external
        ddg = construct_ddg(dataflow)

        self.assertIn(produced, ddg.slot_node_map)
        self.assertIn(consumer, ddg.op_node_map)

    def test_constructor_reuse_starts_a_fresh_graph(self):
        entry = FakeOp("entry")
        producer = FakeOp("producer")
        value = FakeSlot("value")
        value.defn = producer
        entry.connect(producer)
        producer.connect(value)
        dataflow = FakeDataflow(entry)
        constructor = DDGConstructor()

        first = constructor.construct_from_dataflow(dataflow)
        second = constructor.construct_from_dataflow(dataflow)

        self.assertIsNot(first, second)
        self.assertEqual(first.stats(), second.stats())


def _lower_ddg(source: str, function: str = "f") -> DataDependenceGraph:
    """Build a DDG through the same source lowering used by the CLI."""
    compiler = CompilerContext(None)
    compiler.extractor = Extractor(compiler, verbose=False)
    program = compiler.extractor.extract_from_source(source, filename="<ddg-test>")
    code = next(code for code in program.liveCode if code.codeName() == function)
    return construct_ddg(convert.evaluateCode(compiler, code))


def _memory_edges_by_line(ddg: DataDependenceGraph):
    edges = set()
    for node in ddg.nodes:
        for edge in node.edges_out:
            if edge.kind != "memory":
                continue
            source_span = syntax_source_span(getattr(edge.source.ir_node, "op", None))
            target_span = syntax_source_span(getattr(edge.target.ir_node, "op", None))
            if source_span is None or target_span is None:
                continue
            edges.add((edge.label, source_span.start_line, target_span.start_line))
    return edges


class TestLoweredMemoryDependencies(unittest.TestCase):
    """Memory dependences must survive real dataflow lowering.

    The hand-built FakeSlot tests above use one slot object for both reads and
    writes.  Lowered IR creates a new FieldNode per value version, so those
    tests did not catch version-keyed WAR/WAW regressions.
    """

    SOURCE = """def f(c):
    c.x = 1
    y = c.x
    c.x = 2
    return y
"""

    def test_field_read_write_dependencies_have_distinct_labels(self):
        ddg = _lower_ddg(self.SOURCE)
        edges = _memory_edges_by_line(ddg)

        self.assertIn(("RAW", 2, 3), edges)
        self.assertIn(("WAR", 3, 4), edges)
        self.assertIn(("WAW", 2, 4), edges)
        # A store is not a true read: it must not produce RAW from the
        # previous store to the next store.
        self.assertNotIn(("RAW", 2, 4), edges)

    def test_distinct_field_stores_do_not_scale_quadratically(self):
        count = 400
        source = "def f(o, x):\n" + "".join(f"    o.a{i} = x\n" for i in range(count))
        import time

        started = time.time()
        ddg = _lower_ddg(source)
        elapsed = time.time() - started
        self.assertGreater(len(ddg.nodes), count)
        self.assertLess(elapsed, 2.0)


class TestSplitOptimize(unittest.TestCase):
    def test_optimize_clears_removed_output_definition(self):
        split = df.Split(None)
        value = df.LocalNode(None, ())
        output = df.LocalNode(None, ())
        split.read = value
        output.defn = split
        split.modifies = [output]

        split.optimize()

        self.assertIsNone(output.defn)
        self.assertIs(output.canonical(), output)


class TestDDGDumpRegression(unittest.TestCase):
    def test_dump_preserves_edge_labels_and_node_identity(self):
        ddg = DataDependenceGraph()
        producer = ddg.get_or_create_op_node("producer")
        slot = ddg.get_or_create_slot_node("slot_x")
        consumer = ddg.get_or_create_op_node("consumer")

        producer.add_edge_to(slot, "def-use", "slot_x")
        slot.add_edge_to(consumer, "def-use", "slot_x")
        ddg.add_mem_dep(producer, consumer, "RAW", location="heap.x")

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
            self.assertTrue(any(edge["location"] == "'heap.x'" for edge in json_output["edges"]))

            with open(dot_path) as f:
                dot_output = f.read()
            self.assertIn("def-use:slot_x", dot_output)
            self.assertIn("'producer'", dot_output)


if __name__ == "__main__":
    unittest.main()
