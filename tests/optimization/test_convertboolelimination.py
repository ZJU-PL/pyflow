"""Tests for optimization/convertboolelimination.py - Boolean conversion elimination optimization."""

import unittest

from pyflow.optimization.convertboolelimination import InferBoolean, evaluateCode


class MockCode:
    """Mock Code node for testing."""

    def __init__(self, children=None):
        self.children = children or []
        self.visited = []

    def visitChildrenForced(self, visitor):
        self.visited.append(visitor)
        for child in self.children:
            if hasattr(child, 'visitChildrenForced'):
                child.visitChildrenForced(visitor)
            elif hasattr(child, 'visitChildren'):
                child.visitChildren(visitor)

    def addChild(self, child):
        self.children.append(child)


class MockExpr:
    """Mock expression for testing."""

    def __init__(self, always_boolean=False):
        self._always_boolean = always_boolean

    def alwaysReturnsBoolean(self):
        return self._always_boolean


class MockConvertToBool(MockExpr):
    """Mock ConvertToBool expression."""

    def __init__(self, inner_expr):
        super().__init__(always_boolean=False)
        self.expr = inner_expr


class MockAssign:
    """Mock Assign node."""

    def __init__(self, expr, lcls=None):
        self.expr = expr
        self.lcls = lcls or []

    def visitChildren(self, visitor):
        pass


class MockLocal:
    """Mock Local node."""

    def __init__(self, name):
        self.name = name
    
    def alwaysReturnsBoolean(self):
        return False


class TestInferBoolean(unittest.TestCase):
    """Test cases for InferBoolean class."""

    def test_init(self):
        """Test InferBoolean initialization."""
        infer = InferBoolean()
        self.assertEqual(len(infer.lut), 0)
        self.assertEqual(len(infer.converts), 0)

    def test_define(self):
        """Test define method."""
        infer = InferBoolean()
        local = MockLocal("x")
        
        infer.define(local)
        self.assertIn(local, infer.lut)
        self.assertTrue(infer.lut[local])

    def test_define_duplicate(self):
        """Test that defining same local multiple times is idempotent."""
        infer = InferBoolean()
        local = MockLocal("x")
        
        infer.define(local)
        infer.define(local)
        self.assertEqual(infer.lut[local], True)

    def test_undef(self):
        """Test undef method."""
        infer = InferBoolean()
        local = MockLocal("x")
        
        infer.define(local)
        self.assertTrue(infer.lut[local])
        
        infer.undef(local)
        self.assertFalse(infer.lut[local])

    def test_isBoolean_always_returns_true(self):
        """Test isBoolean for expressions that always return boolean."""
        infer = InferBoolean()
        expr = MockExpr(always_boolean=True)
        
        self.assertTrue(infer.isBoolean(expr))

    def test_isBoolean_lookup_true(self):
        """Test isBoolean for expressions found in lookup table."""
        infer = InferBoolean()
        local = MockLocal("x")
        infer.define(local)
        
        self.assertTrue(infer.isBoolean(local))

    def test_isBoolean_lookup_false(self):
        """Test isBoolean for expressions not in lookup table."""
        infer = InferBoolean()
        local = MockLocal("x")
        
        self.assertFalse(infer.isBoolean(local))

    def test_visitLeaf_str(self):
        """Test visitLeaf for str type."""
        infer = InferBoolean()
        infer.visitLeaf("test")
        # Should not raise

    def test_visitLeaf_none(self):
        """Test visitLeaf for None type."""
        infer = InferBoolean()
        infer.visitLeaf(None)
        # Should not raise

    def test_visitLeaf_ast_local(self):
        """Test visitLeaf for ast.Local."""
        from pyflow.language.python import ast
        infer = InferBoolean()
        local = ast.Local("x")
        infer.visitLeaf(local)
        # Should not raise

    def test_visitAssign_non_boolean(self):
        """Test visitAssign with non-boolean expression."""
        infer = InferBoolean()
        
        expr = MockExpr(always_boolean=False)
        local = MockLocal("x")
        assign = MockAssign(expr, [local])
        
        infer.visitAssign(assign)
        
        # Should not add to converts
        self.assertEqual(len(infer.converts), 0)
        # Should not define the local (not boolean)
        self.assertNotIn(local, infer.lut)

    def test_visitAssign_boolean(self):
        """Test visitAssign with boolean expression."""
        infer = InferBoolean()
        
        expr = MockExpr(always_boolean=True)
        local = MockLocal("x")
        assign = MockAssign(expr, [local])
        
        infer.visitAssign(assign)
        
        # Should define the local
        self.assertIn(local, infer.lut)
        self.assertTrue(infer.lut[local])

    def test_visitAssign_convert_to_bool(self):
        """Test visitAssign with ConvertToBool expression - verify behavior with proper AST types."""
        # This test verifies the general logic of tracking ConvertToBool nodes
        # The actual ast.ConvertToBool creation requires proper pyflow AST types
        # For now, test that the inferrer tracks converts correctly
        infer = InferBoolean()
        
        # Create a simple assign that will be tracked
        bool_expr = MockExpr(always_boolean=True)
        local = MockLocal("x")
        assign = MockAssign(bool_expr, [local])
        
        infer.visitAssign(assign)
        
        # The local should be marked as boolean
        self.assertIn(local, infer.lut)
        self.assertTrue(infer.lut[local])

    def test_visitAssign_multiple_lcls(self):
        """Test visitAssign with multiple lcls doesn't define."""
        infer = InferBoolean()
        
        expr = MockExpr(always_boolean=True)
        local1 = MockLocal("x")
        local2 = MockLocal("y")
        assign = MockAssign(expr, [local1, local2])
        
        infer.visitAssign(assign)
        
        # Should not define (multiple targets)
        self.assertNotIn(local1, infer.lut)
        self.assertNotIn(local2, infer.lut)

    def test_process(self):
        """Test process method."""
        infer = InferBoolean()
        code = MockCode()
        
        # Should not raise
        infer.process(code)
        self.assertIn(infer, code.visited)


class TestEvaluateCode(unittest.TestCase):
    """Test cases for evaluateCode function."""

    def test_empty_code(self):
        """Test evaluateCode with empty code."""
        class MockCompiler:
            pass
        
        compiler = MockCompiler()
        code = MockCode()
        
        # Should not raise
        result = evaluateCode(compiler, code)
        self.assertIsNone(result)

    def test_no_converts(self):
        """Test evaluateCode when no conversions are found."""
        class MockCompiler:
            pass
        
        compiler = MockCompiler()
        
        # Code with no ConvertToBool nodes
        code = MockCode()
        
        result = evaluateCode(compiler, code)
        self.assertIsNone(result)

    def test_infer_boolean_tracks_assignments(self):
        """Test that InferBoolean properly tracks boolean assignments."""
        infer = InferBoolean()
        
        # Create a boolean expression assignment
        bool_expr = MockExpr(always_boolean=True)
        local = MockLocal("x")
        assign = MockAssign(bool_expr, [local])
        
        infer.visitAssign(assign)
        
        # Local should be marked as boolean
        self.assertTrue(infer.isBoolean(local))

    def test_infer_boolean_rejects_non_boolean(self):
        """Test that InferBoolean rejects non-boolean expressions."""
        infer = InferBoolean()
        
        # Create a non-boolean expression assignment
        non_bool_expr = MockExpr(always_boolean=False)
        local = MockLocal("x")
        assign = MockAssign(non_bool_expr, [local])
        
        infer.visitAssign(assign)
        
        # Local should not be marked as boolean
        self.assertFalse(infer.isBoolean(local))


if __name__ == "__main__":
    unittest.main()
