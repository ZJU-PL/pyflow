"""Tests for optimization/loadelimination.py."""

import unittest

from types import SimpleNamespace

from pyflow.language.python import ast
from pyflow.optimization.loadelimination import RedundantLoadEliminator


class TestRedundantLoadEliminator(unittest.TestCase):
    def test_find_load_stores_uses_write_numbers_for_stores(self):
        obj = ast.Local("obj")
        name = ast.Local("name")
        dst = ast.Local("dst")
        value = ast.Local("value")

        load_expr = ast.Load(obj, "LowLevel", name)
        load_expr.annotation = SimpleNamespace(reads=((name,),))
        load_assign = ast.Assign(load_expr, [dst])

        store = ast.Store(obj, "LowLevel", name, value)
        store.annotation = SimpleNamespace(modifies=((name,),))

        eliminator = RedundantLoadEliminator(
            compiler=None,
            prgm=None,
            readNumbers={(load_assign, obj): 1, (load_assign, name): 2},
            writeNumbers={(store, name): 3},
            dom={},
        )

        loads, stores = eliminator.findLoadStores()

        self.assertEqual(loads, {load_assign})
        self.assertEqual(stores, {store})

    def test_make_read_sig_unsupported_arg_is_skipped(self):
        eliminator = RedundantLoadEliminator(
            compiler=None,
            prgm=None,
            readNumbers={},
            writeNumbers={},
            dom={},
        )

        self.assertIsNone(eliminator.makeReadSig(None, object()))

    def test_generate_replacements_handles_multiple_stores_for_same_signature(self):
        obj = ast.Local("obj")
        name = ast.Local("name")
        value1 = ast.Local("value1")
        value2 = ast.Local("value2")
        dst = ast.Local("dst")

        store1 = ast.Store(obj, "LowLevel", name, value1)
        store2 = ast.Store(obj, "LowLevel", name, value2)
        load_expr = ast.Load(obj, "LowLevel", name)
        load_expr.annotation = SimpleNamespace(reads=((name,),))
        load = ast.Assign(load_expr, [dst])

        eliminator = RedundantLoadEliminator(
            compiler=None,
            prgm=None,
            readNumbers={},
            writeNumbers={},
            dom={store1: (1, 6), store2: (2, 5), load: (3, 4)},
        )

        signatures = {
            ("sig",): {
                "loads": [load],
                "stores": [store1, store2],
            }
        }

        replacements = eliminator.generateReplacements(signatures)

        self.assertIn(load, replacements)
        self.assertNotIn(store1, replacements)
        self.assertIsInstance(replacements[load], ast.Assign)
        self.assertEqual(eliminator.eliminated, 1)


if __name__ == "__main__":
    unittest.main()
