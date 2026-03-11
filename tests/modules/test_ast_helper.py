import ast
import os
import tempfile
import unittest

from pyflow.language.modules.ast_helper import Arguments, generate_ast


class TestAstHelper(unittest.TestCase):
    def test_generate_ast_import_and_parse(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write("def f():\n    return 1\n")
            path = handle.name

        try:
            tree = generate_ast(path)
            self.assertIsInstance(tree, ast.Module)
        finally:
            os.unlink(path)

    def test_arguments_varargs_and_kwargs_not_split_into_characters(self):
        func = ast.parse("def f(a, *args, **kwargs):\n    return 1\n").body[0]
        parsed = Arguments(func.args)
        self.assertEqual(parsed.arguments, ["a", "args", "kwargs"])


if __name__ == "__main__":
    unittest.main()
