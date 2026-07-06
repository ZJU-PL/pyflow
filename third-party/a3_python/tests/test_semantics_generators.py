"""
Tests for generator and async/await bytecode semantics.

Tests the symbolic execution of generator functions and async/await constructs.
Target: Python 3.11+ generator/coroutine opcodes.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


class TestGeneratorOpcodes:
    """Test basic generator opcode execution."""
    
    def test_simple_generator_creation(self):
        """Test that generator functions can be created (RETURN_GENERATOR)."""
        code = compile("""
def gen():
    yield 1
    yield 2
gen()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should complete without crashing
        assert len(paths) > 0
        # Should not have unhandled exceptions
        for path in paths:
            if path.state.exception:
                # RETURN_GENERATOR itself shouldn't cause exceptions
                assert "NotImplementedError" not in str(path.state.exception)
    
    def test_yield_value_opcode(self):
        """Test YIELD_VALUE opcode execution."""
        code = compile("""
def gen():
    yield 42
g = gen()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should handle yield without errors
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0
    
    def test_generator_with_multiple_yields(self):
        """Test generator with multiple yield statements."""
        code = compile("""
def gen():
    yield 1
    yield 2
    yield 3
g = gen()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should explore generator definition without error
        assert len(paths) > 0


class TestAsyncOpcodes:
    """Test async/await opcode execution."""
    
    def test_simple_async_function(self):
        """Test basic async function (coroutine) creation."""
        code = compile("""
async def coro():
    return 42
coro()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should handle RETURN_GENERATOR for coroutine
        assert len(paths) > 0
        for path in paths:
            if path.state.exception:
                assert "NotImplementedError" not in str(path.state.exception)
    
    def test_get_awaitable_opcode(self):
        """Test GET_AWAITABLE opcode."""
        # Note: This is a simplified test since full await requires SEND/END_SEND loop
        code = compile("""
async def helper():
    return 1

async def main():
    x = await helper()
    return x
main()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should handle awaitable creation
        assert len(paths) > 0
    
    def test_send_and_end_send_opcodes(self):
        """Test SEND and END_SEND opcodes in await context."""
        code = compile("""
async def coro():
    return 42

async def main():
    result = await coro()
    return result
main()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should handle send/end_send sequence
        assert len(paths) > 0


class TestAsyncIteration:
    """Test async for loops and async iteration."""
    
    def test_get_aiter_opcode(self):
        """Test GET_AITER opcode."""
        code = compile("""
async def async_gen():
    yield 1
    yield 2

async def main():
    async for item in async_gen():
        pass
main()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should handle async iteration setup
        assert len(paths) > 0
    
    def test_get_anext_opcode(self):
        """Test GET_ANEXT opcode in async for loop."""
        code = compile("""
class AsyncIter:
    async def __anext__(self):
        return 1
    
    def __aiter__(self):
        return self

async def main():
    async for item in AsyncIter():
        break
main()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should handle anext calls
        assert len(paths) > 0


class TestYieldFrom:
    """Test yield from construct."""
    
    def test_get_yield_from_iter(self):
        """Test GET_YIELD_FROM_ITER opcode."""
        code = compile("""
def inner():
    yield 1
    yield 2

def outer():
    yield from inner()
outer()
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should handle yield from setup
        assert len(paths) > 0


class TestGeneratorSemantics:
    """Test generator semantics for bug detection."""
    
    def test_generator_does_not_immediately_execute(self):
        """Test that calling a generator doesn't immediately execute its body."""
        # This is a semantic property: generator functions return generator objects
        # without executing the body until next() is called
        code = compile("""
def gen():
    x = 1 / 0  # Would raise if executed immediately
    yield x

g = gen()  # Should not raise here
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should complete without div-by-zero at generator creation
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted and not p.state.exception]
        # At least one path should complete successfully (generator creation path)
        assert len(completed) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
