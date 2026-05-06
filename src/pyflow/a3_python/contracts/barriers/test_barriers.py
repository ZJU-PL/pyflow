"""
Comprehensive Test Suite for Barrier-Based Contracts Framework

This module tests the barrier framework including:
1. Interval domain operations
2. Device abstraction
3. Shape abstraction  
4. Deferred barriers
5. Contract registry
6. Device analyzer
7. PyTorch contracts
"""

import unittest
import sys
import ast
from pathlib import Path
from typing import List, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


class TestIntervalDomain(unittest.TestCase):
    """Test the interval abstract domain."""
    
    def test_interval_creation(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        # Basic interval
        i = Interval(0, 10)
        self.assertEqual(i.lo, 0)
        self.assertEqual(i.hi, 10)
        
        # Unit interval
        unit = Interval(0, 1)
        self.assertEqual(unit.lo, 0)
        self.assertEqual(unit.hi, 1)
        
    def test_interval_contains(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        i = Interval(-5, 5)
        self.assertTrue(i.contains(0))
        self.assertTrue(i.contains(-5))
        self.assertTrue(i.contains(5))
        self.assertFalse(i.contains(10))
        
    def test_interval_arithmetic(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        a = Interval(1, 3)
        b = Interval(2, 4)
        
        # Addition
        add = a + b
        self.assertEqual(add.lo, 3)
        self.assertEqual(add.hi, 7)
        
        # Subtraction
        sub = a - b
        self.assertEqual(sub.lo, -3)
        self.assertEqual(sub.hi, 1)
        
    def test_interval_multiplication(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        a = Interval(-2, 3)
        b = Interval(1, 2)
        
        mul = a * b
        self.assertEqual(mul.lo, -4)  # -2 * 2
        self.assertEqual(mul.hi, 6)   # 3 * 2
        
    def test_interval_union(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        a = Interval(0, 5)
        b = Interval(3, 10)
        
        union = a.union(b)
        self.assertEqual(union.lo, 0)
        self.assertEqual(union.hi, 10)
        
    def test_interval_intersection(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        a = Interval(0, 5)
        b = Interval(3, 10)
        
        inter = a.intersection(b)
        self.assertEqual(inter.lo, 3)
        self.assertEqual(inter.hi, 5)
        
    def test_interval_functions(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        i = Interval(-1, 1)
        
        # Sigmoid
        sig = i.sigmoid()
        self.assertGreaterEqual(sig.lo, 0)
        self.assertLessEqual(sig.hi, 1)
        
        # Tanh
        tanh = i.tanh()
        self.assertGreaterEqual(tanh.lo, -1)
        self.assertLessEqual(tanh.hi, 1)
        
        # ReLU
        relu = i.relu()
        self.assertEqual(relu.lo, 0)
        self.assertEqual(relu.hi, 1)


class TestDeviceAbstraction(unittest.TestCase):
    """Test device abstraction for device barrier checking."""
    
    def test_device_creation(self):
        from a3_python.contracts.barriers.abstract_values import Device
        
        cpu = Device("cpu")
        cuda0 = Device("cuda", 0)
        cuda1 = Device("cuda", 1)
        
        self.assertEqual(cpu.device_type, "cpu")
        self.assertEqual(cuda0.device_type, "cuda")
        self.assertEqual(cuda0.index, 0)
        
    def test_device_compatibility(self):
        from a3_python.contracts.barriers.abstract_values import Device
        
        cpu = Device("cpu")
        cuda0 = Device("cuda", 0)
        cuda1 = Device("cuda", 1)
        
        # CPU and CUDA are NOT compatible
        self.assertFalse(cpu.compatible_with(cuda0))
        
        # Different CUDA devices are NOT compatible
        self.assertFalse(cuda0.compatible_with(cuda1))
        
        # Same device is compatible
        self.assertTrue(cpu.compatible_with(cpu))
        self.assertTrue(cuda0.compatible_with(cuda0))
        
    def test_device_string_conversion(self):
        from a3_python.contracts.barriers.abstract_values import Device
        
        cpu = Device("cpu")
        cuda0 = Device("cuda", 0)
        
        self.assertEqual(str(cpu), "cpu")
        self.assertEqual(str(cuda0), "cuda:0")


class TestShapeAbstraction(unittest.TestCase):
    """Test shape abstraction."""
    
    def test_shape_creation(self):
        from a3_python.contracts.barriers.abstract_values import Shape
        
        s = Shape([32, 3, 224, 224])
        self.assertEqual(s.dims, [32, 3, 224, 224])
        self.assertEqual(len(s), 4)
        
    def test_shape_broadcast(self):
        from a3_python.contracts.barriers.abstract_values import Shape
        
        a = Shape([32, 1, 224])
        b = Shape([3, 224])
        
        # Broadcasting should work
        self.assertTrue(a.can_broadcast_with(b))
        
    def test_shape_matmul(self):
        from a3_python.contracts.barriers.abstract_values import Shape
        
        a = Shape([32, 64])  # (32, 64)
        b = Shape([64, 128])  # (64, 128)
        
        self.assertTrue(a.can_matmul_with(b))
        result = a.matmul_result_shape(b)
        self.assertEqual(result.dims, [32, 128])


class TestDeferredBarrier(unittest.TestCase):
    """Test deferred barrier functionality."""
    
    def test_barrier_creation(self):
        from a3_python.contracts.barriers.deferred import DeferredBarrier
        from a3_python.contracts.barriers.intervals import Interval
        
        source = Interval(-10, 10)
        barrier = DeferredBarrier(source)
        
        self.assertEqual(barrier.source.lo, -10)
        self.assertEqual(barrier.source.hi, 10)
        
    def test_barrier_transformation(self):
        from a3_python.contracts.barriers.deferred import DeferredBarrier
        from a3_python.contracts.barriers.intervals import Interval
        
        source = Interval(-10, 10)
        barrier = DeferredBarrier(source)
        
        # Apply sigmoid - should narrow to [0, 1]
        barrier.apply_transformation("sigmoid")
        
        current = barrier.current_interval()
        self.assertGreaterEqual(current.lo, 0)
        self.assertLessEqual(current.hi, 1)
        
    def test_barrier_safety_check(self):
        from a3_python.contracts.barriers.deferred import DeferredBarrier
        from a3_python.contracts.barriers.intervals import Interval
        
        source = Interval(1, 10)  # Strictly positive
        barrier = DeferredBarrier(source)
        
        # Division by this should be safe
        result = barrier.check_division_safe()
        self.assertTrue(result.is_safe)


class TestDeviceBarrier(unittest.TestCase):
    """Test PyTorch-specific device barrier."""
    
    def test_device_barrier_creation(self):
        from a3_python.contracts.barriers.deferred import DeviceBarrier
        from a3_python.contracts.barriers.abstract_values import Device
        
        barrier = DeviceBarrier()
        
        cpu = Device("cpu")
        cuda = Device("cuda", 0)
        
        barrier.track_variable("a", cpu)
        barrier.track_variable("b", cuda)
        
        self.assertEqual(barrier.get_device("a").device_type, "cpu")
        self.assertEqual(barrier.get_device("b").device_type, "cuda")
        
    def test_device_barrier_compatibility(self):
        from a3_python.contracts.barriers.deferred import DeviceBarrier
        from a3_python.contracts.barriers.abstract_values import Device
        
        barrier = DeviceBarrier()
        
        cpu = Device("cpu")
        cuda = Device("cuda", 0)
        
        barrier.track_variable("a", cpu)
        barrier.track_variable("b", cuda)
        barrier.track_variable("c", cpu)
        
        # a and b are not compatible (CPU vs CUDA)
        self.assertFalse(barrier.check_compatible("a", "b"))
        
        # a and c are compatible (both CPU)
        self.assertTrue(barrier.check_compatible("a", "c"))


class TestContractRegistry(unittest.TestCase):
    """Test contract registry functionality."""
    
    def test_registry_creation(self):
        from a3_python.contracts.barriers.contracts import ContractRegistry
        
        registry = ContractRegistry()
        self.assertEqual(len(registry), 0)
        
    def test_contract_registration(self):
        from a3_python.contracts.barriers.contracts import (
            ContractRegistry, FunctionContract
        )
        from a3_python.contracts.barriers.intervals import Interval
        
        registry = ContractRegistry()
        
        contract = FunctionContract(
            name="torch.sigmoid",
            qualname="torch.sigmoid",
            param_names=["input"],
            param_intervals={},
            return_interval=Interval(0, 1),
            preconditions=[],
            postconditions=[],
            requires_same_device=False,
            may_raise=[],
            docstring="Sigmoid activation",
        )
        
        registry.register(contract)
        
        # Retrieve contract
        retrieved = registry.get("torch", "sigmoid")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.return_interval.lo, 0)
        self.assertEqual(retrieved.return_interval.hi, 1)


class TestDeviceAnalyzer(unittest.TestCase):
    """Test the AST-based device analyzer."""
    
    def test_simple_device_tracking(self):
        from a3_python.contracts.barriers.device_analyzer import (
            DeviceAnalyzer, analyze_device_mismatches
        )
        
        source = '''
import torch

a = torch.tensor([1.0])
b = a.cuda()
c = a + b  # Mismatch: a is CPU, b is CUDA
'''
        
        bugs = analyze_device_mismatches(source)
        
        # Should detect the mismatch
        self.assertGreater(len(bugs), 0)
        
    def test_no_false_positive(self):
        from a3_python.contracts.barriers.device_analyzer import (
            analyze_device_mismatches
        )
        
        source = '''
import torch

a = torch.tensor([1.0]).cuda()
b = torch.tensor([2.0]).cuda()
c = a + b  # Both on CUDA - OK
'''
        
        bugs = analyze_device_mismatches(source)
        
        # Should NOT detect a mismatch
        self.assertEqual(len(bugs), 0)
        
    def test_device_transfer_tracking(self):
        from a3_python.contracts.barriers.device_analyzer import (
            analyze_device_mismatches
        )
        
        source = '''
import torch

x = torch.randn(10)  # CPU
x = x.cuda()         # Now CUDA
y = torch.randn(10).cuda()  # CUDA
z = x + y  # Both CUDA now - OK
'''
        
        bugs = analyze_device_mismatches(source)
        self.assertEqual(len(bugs), 0)


class TestTorchContracts(unittest.TestCase):
    """Test PyTorch contract registration."""
    
    def test_load_all_contracts(self):
        from a3_python.contracts.barriers.torch import (
            register_all_torch_contracts
        )
        from a3_python.contracts.barriers.contracts import ContractRegistry
        
        registry = ContractRegistry()
        register_all_torch_contracts(registry)
        
        # Should have many contracts
        self.assertGreater(len(registry), 100)
        
    def test_core_contracts(self):
        from a3_python.contracts.barriers.torch import get_torch_contract
        
        # Test sigmoid contract
        sigmoid = get_torch_contract("torch", "sigmoid")
        if sigmoid:
            self.assertIsNotNone(sigmoid.return_interval)
            self.assertEqual(sigmoid.return_interval.lo, 0)
            self.assertEqual(sigmoid.return_interval.hi, 1)
            
    def test_requires_same_device(self):
        from a3_python.contracts.barriers.torch import get_torch_contract
        
        # torch.add requires same device
        add = get_torch_contract("torch", "add")
        if add:
            self.assertTrue(add.requires_same_device)


class TestIntervalTransformations(unittest.TestCase):
    """Test mathematical function interval transformations."""
    
    def test_exp_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        i = Interval(0, 1)
        exp_i = i.exp()
        
        # e^0 = 1, e^1 ≈ 2.718
        self.assertAlmostEqual(exp_i.lo, 1.0, places=5)
        self.assertAlmostEqual(exp_i.hi, 2.718281828, places=5)
        
    def test_log_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        i = Interval(1, 10)
        log_i = i.log()
        
        # log(1) = 0, log(10) ≈ 2.302
        self.assertAlmostEqual(log_i.lo, 0.0, places=5)
        self.assertAlmostEqual(log_i.hi, 2.302585, places=5)
        
    def test_sqrt_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        i = Interval(4, 9)
        sqrt_i = i.sqrt()
        
        self.assertAlmostEqual(sqrt_i.lo, 2.0, places=5)
        self.assertAlmostEqual(sqrt_i.hi, 3.0, places=5)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def test_empty_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        # Interval with lo > hi is empty
        empty = Interval(5, 3)
        self.assertTrue(empty.is_empty())
        
    def test_infinite_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        pos_inf = Interval(0, float('inf'))
        self.assertTrue(pos_inf.contains(1000000))
        
        neg_inf = Interval(float('-inf'), 0)
        self.assertTrue(neg_inf.contains(-1000000))
        
    def test_division_by_zero_interval(self):
        from a3_python.contracts.barriers.intervals import Interval
        
        a = Interval(1, 2)
        b = Interval(-1, 1)  # Contains 0
        
        # Division by interval containing 0 should give infinite interval
        result = a / b
        self.assertTrue(float('-inf') <= result.lo or result.hi >= float('inf'))


class TestContractBuilder(unittest.TestCase):
    """Test the fluent contract builder API."""
    
    def test_builder_basic(self):
        from a3_python.contracts.barriers.contracts import ContractBuilder
        from a3_python.contracts.barriers.intervals import Interval
        
        builder = ContractBuilder("torch.relu")
        contract = (builder
            .with_param("input", Interval(float('-inf'), float('inf')))
            .returns(Interval(0, float('inf')))
            .requires_same_device()
            .build())
        
        self.assertEqual(contract.name, "torch.relu")
        self.assertTrue(contract.requires_same_device)
        self.assertEqual(contract.return_interval.lo, 0)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
