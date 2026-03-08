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


if __name__ == "__main__":
    unittest.main()
