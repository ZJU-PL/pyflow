"""
Device Barrier Analyzer

This module provides the core analysis logic for detecting device mismatch
errors in PyTorch code. It integrates with the barrier-based contract system
to track tensor devices through program execution and detect when operations
attempt to combine tensors on incompatible devices.

The analyzer uses abstract interpretation over the Device domain:
- Tracks device assignments for each variable
- Propagates devices through function calls using contracts
- Detects incompatible device operations (e.g., CPU + CUDA)

Example detected error:
    a = torch.tensor([1.0]).cuda()  # Device: CUDA:0
    b = torch.tensor([2.0])          # Device: CPU
    c = torch.add(a, b)              # ERROR: requires_same_device but CPU != CUDA:0
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import ast
from collections import defaultdict

from .abstract_values import Device, DeviceType, AbstractTensor
from .deferred import DeviceBarrier, DeferredBarrier, TransformationTrace
from .contracts import ContractRegistry, LibraryContract, FunctionContract
from .torch import TORCH_REGISTRY, get_torch_contract, register_all_torch_contracts


@dataclass
class DeviceMismatchBug:
    """Represents a detected device mismatch bug."""
    
    line: int
    column: int
    message: str
    function_name: str
    device1: Device
    device2: Device
    variable1: str
    variable2: str
    severity: str = "error"
    
    def __str__(self) -> str:
        return (
            f"Device mismatch at line {self.line}: {self.message}\n"
            f"  {self.variable1} is on {self.device1}\n"
            f"  {self.variable2} is on {self.device2}\n"
            f"  Operation: {self.function_name}"
        )


@dataclass 
class AnalysisState:
    """State maintained during analysis."""
    
    # Variable -> Device mapping
    device_map: Dict[str, Device] = field(default_factory=dict)
    
    # Variable -> AbstractTensor mapping (includes device, shape, dtype)
    tensor_map: Dict[str, AbstractTensor] = field(default_factory=dict)
    
    # Active device barriers
    barriers: List[DeviceBarrier] = field(default_factory=list)
    
    # Detected bugs
    bugs: List[DeviceMismatchBug] = field(default_factory=list)
    
    # Function call stack for context
    call_stack: List[str] = field(default_factory=list)
    
    def copy(self) -> 'AnalysisState':
        """Create a deep copy of the state."""
        return AnalysisState(
            device_map=dict(self.device_map),
            tensor_map=dict(self.tensor_map),
            barriers=list(self.barriers),
            bugs=list(self.bugs),
            call_stack=list(self.call_stack),
        )
    
    def merge(self, other: 'AnalysisState') -> 'AnalysisState':
        """Merge two states (for control flow joins)."""
        merged = AnalysisState()
        
        # Merge device maps with join
        all_vars = set(self.device_map.keys()) | set(other.device_map.keys())
        for var in all_vars:
            dev1 = self.device_map.get(var, Device.unknown())
            dev2 = other.device_map.get(var, Device.unknown())
            merged.device_map[var] = Device.join(dev1, dev2)
        
        # Collect all bugs (deduplicate without relying on dataclass hashability)
        bug_map = {}
        for bug in self.bugs + other.bugs:
            key = (
                bug.line,
                bug.column,
                bug.function_name,
                bug.message,
                str(bug.device1),
                str(bug.device2),
                bug.variable1,
                bug.variable2,
            )
            bug_map[key] = bug
        merged.bugs = list(bug_map.values())
        
        # Merge barriers
        merged.barriers = list(self.barriers) + list(other.barriers)
        
        return merged
    
    def set_device(self, var: str, device: Device) -> None:
        """Set device for a variable."""
        self.device_map[var] = device
        
        # Also update tensor map if exists
        if var in self.tensor_map:
            prev = self.tensor_map[var]
            self.tensor_map[var] = AbstractTensor(
                device=device,
                shape=prev.shape,
                dtype=prev.dtype,
                element_bounds=getattr(prev, "element_bounds", None) or prev.element_bounds,
                is_contiguous=prev.is_contiguous,
                requires_grad=prev.requires_grad,
                is_leaf=prev.is_leaf,
                is_normalized=prev.is_normalized,
                is_probability=prev.is_probability,
                is_one_hot=prev.is_one_hot,
                is_positive_definite=prev.is_positive_definite,
                is_symmetric=prev.is_symmetric,
            )
        else:
            self.tensor_map[var] = AbstractTensor(device=device)
    
    def get_device(self, var: str) -> Device:
        """Get device for a variable."""
        return self.device_map.get(var, Device.unknown())


class DeviceAnalyzer(ast.NodeVisitor):
    """
    AST visitor that tracks tensor devices through program execution.
    
    Uses barrier-based contracts to:
    1. Track device assignments (x.cuda(), x.to('cpu'), etc.)
    2. Propagate devices through operations
    3. Detect incompatible device operations
    """
    
    def __init__(self, registry: ContractRegistry = None):
        """
        Initialize the analyzer.
        
        Args:
            registry: Contract registry to use. Defaults to TORCH_REGISTRY.
        """
        self.registry = registry or TORCH_REGISTRY
        if len(self.registry) == 0:
            register_all_torch_contracts(self.registry)
        
        self.state = AnalysisState()
        self.current_line = 0
        self.current_col = 0
    
    def analyze(self, source: str) -> List[DeviceMismatchBug]:
        """
        Analyze source code for device mismatch bugs.
        
        Args:
            source: Python source code to analyze.
            
        Returns:
            List of detected device mismatch bugs.
        """
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return []
        
        self.state = AnalysisState()
        self.visit(tree)
        return self.state.bugs
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Handle assignment statements."""
        self.current_line = node.lineno
        self.current_col = node.col_offset
        
        # Analyze the value expression
        value_device = self._analyze_expr(node.value)
        
        # Assign device to all targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.state.set_device(target.id, value_device)
            elif isinstance(target, ast.Tuple):
                # Handle tuple unpacking
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self.state.set_device(elt.id, value_device)
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Handle augmented assignment (+=, -=, etc.)."""
        self.current_line = node.lineno
        self.current_col = node.col_offset
        
        if isinstance(node.target, ast.Name):
            target_var = node.target.id
            target_device = self.state.get_device(target_var)
            value_device = self._analyze_expr(node.value)
            
            # Check device compatibility for augmented assignment
            if not target_device.compatible_with(value_device):
                self._report_bug(
                    f"Augmented assignment with incompatible devices",
                    self._get_op_name(node.op),
                    target_device,
                    value_device,
                    target_var,
                    self._expr_to_str(node.value),
                )
        
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For) -> None:
        """Handle for loops with state merging."""
        self.current_line = node.lineno
        
        # Analyze iterator
        iter_device = self._analyze_expr(node.iter)
        
        # Set loop variable device
        if isinstance(node.target, ast.Name):
            self.state.set_device(node.target.id, iter_device)
        
        # Save state before loop
        pre_loop_state = self.state.copy()
        
        # Analyze loop body
        for stmt in node.body:
            self.visit(stmt)
        
        # Merge pre-loop and post-body states (fixed point approximation)
        self.state = pre_loop_state.merge(self.state)
        
        # Analyze else clause if present
        for stmt in node.orelse:
            self.visit(stmt)
    
    def visit_If(self, node: ast.If) -> None:
        """Handle if statements with branch merging."""
        self.current_line = node.lineno
        
        # Analyze condition (might have side effects)
        self._analyze_expr(node.test)
        
        # Save state before branches
        pre_branch_state = self.state.copy()
        
        # Analyze true branch
        for stmt in node.body:
            self.visit(stmt)
        true_state = self.state
        
        # Analyze false branch from pre-branch state
        self.state = pre_branch_state.copy()
        for stmt in node.orelse:
            self.visit(stmt)
        false_state = self.state
        
        # Merge branch states
        self.state = true_state.merge(false_state)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit call expressions for side effects."""
        self.current_line = node.lineno
        self.current_col = node.col_offset
        self._analyze_call(node)
        self.generic_visit(node)
    
    def _analyze_expr(self, node: ast.expr) -> Device:
        """Analyze an expression and return its device."""
        if isinstance(node, ast.Name):
            return self.state.get_device(node.id)
        
        elif isinstance(node, ast.Constant):
            # Constants are on CPU by default
            return Device.cpu()
        
        elif isinstance(node, ast.Call):
            return self._analyze_call(node)
        
        elif isinstance(node, ast.Attribute):
            return self._analyze_attribute(node)
        
        elif isinstance(node, ast.BinOp):
            return self._analyze_binop(node)
        
        elif isinstance(node, ast.UnaryOp):
            return self._analyze_expr(node.operand)
        
        elif isinstance(node, ast.Subscript):
            # Subscripting preserves device
            return self._analyze_expr(node.value)
        
        elif isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            # Container - check all elements are compatible
            if node.elts:
                first_device = self._analyze_expr(node.elts[0])
                for elt in node.elts[1:]:
                    elt_device = self._analyze_expr(elt)
                    if not first_device.compatible_with(elt_device):
                        self._report_bug(
                            "Container elements on different devices",
                            "list/tuple",
                            first_device,
                            elt_device,
                            self._expr_to_str(node.elts[0]),
                            self._expr_to_str(elt),
                        )
                return first_device
            return Device.cpu()
        
        elif isinstance(node, ast.IfExp):
            # Ternary - join both branches
            true_device = self._analyze_expr(node.body)
            false_device = self._analyze_expr(node.orelse)
            return Device.join(true_device, false_device)
        
        return Device.unknown()
    
    def _analyze_call(self, node: ast.Call) -> Device:
        """Analyze a function call and check device compatibility."""
        func_name, module = self._get_function_info(node)
        
        # Get argument devices
        arg_devices = [self._analyze_expr(arg) for arg in node.args]
        
        # Handle special device-changing methods
        if func_name in ('cuda', 'cpu', 'to'):
            return self._handle_device_transfer(node, func_name)
        
        # Look up contract
        contract = get_torch_contract(module, func_name)
        
        if contract and isinstance(contract, FunctionContract):
            # Check device requirements
            if contract.requires_same_device and len(arg_devices) >= 2:
                for i, dev1 in enumerate(arg_devices):
                    for j, dev2 in enumerate(arg_devices[i+1:], i+1):
                        if not dev1.compatible_with(dev2):
                            self._report_bug(
                                f"Function requires same device for all arguments",
                                f"{module}.{func_name}",
                                dev1,
                                dev2,
                                self._expr_to_str(node.args[i]) if i < len(node.args) else "arg",
                                self._expr_to_str(node.args[j]) if j < len(node.args) else "arg",
                            )
                            return Device.unknown()
            
            # Determine output device
            if contract.preserves_device and arg_devices:
                return arg_devices[0]
        
        # Default: return device of first tensor argument
        return arg_devices[0] if arg_devices else Device.unknown()
    
    def _analyze_attribute(self, node: ast.Attribute) -> Device:
        """Analyze attribute access."""
        # Handle method calls like x.cuda()
        if isinstance(node.ctx, ast.Load):
            # Accessing an attribute - get device of base object
            return self._analyze_expr(node.value)
        return Device.unknown()
    
    def _analyze_binop(self, node: ast.BinOp) -> Device:
        """Analyze binary operations."""
        left_device = self._analyze_expr(node.left)
        right_device = self._analyze_expr(node.right)
        
        # Binary ops require same device
        if not left_device.compatible_with(right_device):
            self._report_bug(
                f"Binary operation with incompatible devices",
                self._get_op_name(node.op),
                left_device,
                right_device,
                self._expr_to_str(node.left),
                self._expr_to_str(node.right),
            )
            return Device.unknown()
        
        return left_device
    
    def _handle_device_transfer(self, node: ast.Call, method: str) -> Device:
        """Handle device transfer methods like .cuda(), .cpu(), .to()."""
        if method == 'cuda':
            # Check for device index
            if node.args:
                # cuda(device_index)
                return Device.cuda(0)  # Simplified
            return Device.cuda()
        
        elif method == 'cpu':
            return Device.cpu()
        
        elif method == 'to':
            # Parse .to() arguments
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    if isinstance(arg.value, str):
                        if 'cuda' in arg.value.lower():
                            return Device.cuda()
                        elif 'cpu' in arg.value.lower():
                            return Device.cpu()
                        elif 'mps' in arg.value.lower():
                            return Device.mps()
                elif isinstance(arg, ast.Name):
                    # Variable device - unknown
                    return Device.unknown()
            
            # Check keyword arguments
            for kw in node.keywords:
                if kw.arg == 'device':
                    if isinstance(kw.value, ast.Constant):
                        val = kw.value.value
                        if isinstance(val, str):
                            if 'cuda' in val.lower():
                                return Device.cuda()
                            elif 'cpu' in val.lower():
                                return Device.cpu()
            
            return Device.unknown()
        
        return Device.unknown()
    
    def _get_function_info(self, node: ast.Call) -> Tuple[str, str]:
        """Extract function name and module from a call node."""
        if isinstance(node.func, ast.Attribute):
            # Method call like torch.add() or x.cuda()
            func_name = node.func.attr
            
            if isinstance(node.func.value, ast.Attribute):
                # Nested like torch.nn.functional.relu
                parts = []
                current = node.func.value
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                parts.reverse()
                module = '.'.join(parts)
            elif isinstance(node.func.value, ast.Name):
                # Simple like torch.add
                module = node.func.value.id
            else:
                # Method on expression result
                module = ""
            
            return func_name, module
        
        elif isinstance(node.func, ast.Name):
            # Direct function call
            return node.func.id, ""
        
        return "", ""
    
    def _get_op_name(self, op: ast.operator) -> str:
        """Get string name for an operator."""
        op_names = {
            ast.Add: "add",
            ast.Sub: "sub",
            ast.Mult: "mul",
            ast.Div: "div",
            ast.FloorDiv: "floordiv",
            ast.Mod: "mod",
            ast.Pow: "pow",
            ast.MatMult: "matmul",
            ast.BitAnd: "bitwise_and",
            ast.BitOr: "bitwise_or",
            ast.BitXor: "bitwise_xor",
        }
        return op_names.get(type(op), "op")
    
    def _expr_to_str(self, node: ast.expr) -> str:
        """Convert an expression to a string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Attribute):
            base = self._expr_to_str(node.value)
            return f"{base}.{node.attr}"
        elif isinstance(node, ast.Call):
            func = self._expr_to_str(node.func)
            return f"{func}(...)"
        elif isinstance(node, ast.BinOp):
            left = self._expr_to_str(node.left)
            right = self._expr_to_str(node.right)
            return f"({left} op {right})"
        return "<expr>"
    
    def _report_bug(self, message: str, function: str,
                    dev1: Device, dev2: Device, 
                    var1: str, var2: str) -> None:
        """Report a device mismatch bug."""
        bug = DeviceMismatchBug(
            line=self.current_line,
            column=self.current_col,
            message=message,
            function_name=function,
            device1=dev1,
            device2=dev2,
            variable1=var1,
            variable2=var2,
        )
        self.state.bugs.append(bug)


def analyze_device_mismatches(source: str) -> List[DeviceMismatchBug]:
    """
    Analyze source code for device mismatch bugs.
    
    This is the main entry point for device barrier analysis.
    
    Args:
        source: Python source code to analyze.
        
    Returns:
        List of detected device mismatch bugs.
        
    Example:
        source = '''
        a = torch.tensor([1.0]).cuda()
        b = torch.tensor([2.0])
        c = a + b  # Bug: CPU + CUDA
        '''
        
        bugs = analyze_device_mismatches(source)
        for bug in bugs:
            print(bug)
    """
    analyzer = DeviceAnalyzer()
    return analyzer.analyze(source)


# Example usage and testing
if __name__ == "__main__":
    test_code = '''
import torch

# Good: Same device
a = torch.tensor([1.0]).cuda()
b = torch.tensor([2.0]).cuda()
c = a + b  # OK

# Bad: Different devices
x = torch.tensor([1.0]).cuda()
y = torch.tensor([2.0])  # CPU
z = torch.add(x, y)  # ERROR!

# Bad: Binary operation
m = torch.tensor([1.0]).cuda()
n = torch.tensor([2.0]).cpu()
p = m * n  # ERROR!
'''
    
    bugs = analyze_device_mismatches(test_code)
    print(f"Found {len(bugs)} device mismatch bugs:")
    for bug in bugs:
        print(f"  Line {bug.line}: {bug.message}")
        print(f"    {bug.variable1} on {bug.device1}")
        print(f"    {bug.variable2} on {bug.device2}")
        print()
