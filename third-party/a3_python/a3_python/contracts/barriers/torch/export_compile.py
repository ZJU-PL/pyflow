"""
PyTorch Export and Compile Contracts - torch.export and torch.compile

This module provides contracts for PyTorch's new export and compilation APIs:
- torch.export (program capture and export)
- torch.compile (dynamo compilation)
- torch.fx (graph manipulation)
- torch._dynamo (dynamo internals)

Device Barrier Considerations:
- Exported programs preserve device placement
- Compilation may have device-specific optimizations
- FX graphs capture device information
"""

from typing import Dict, List, Any, Optional, Callable
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    MethodContract,
    ModuleContract,
    PropertyContract,
)


# ============================================================================
# torch.export - Program Export
# ============================================================================

def _register_export(registry: ContractRegistry) -> None:
    """Register torch.export contracts."""
    
    # torch.export.export
    registry.register(FunctionContract(
        name="torch.export.export",
        qualname="torch.export.export",
        param_names=["f", "args", "kwargs", "dynamic_shapes", "strict",
                    "preserve_module_call_signature"],
        param_intervals={},
        return_interval=None,  # Returns ExportedProgram
        preconditions=[
            ("callable_model", "f must be callable (module or function)"),
            ("valid_args", "args must match function signature"),
        ],
        postconditions=[
            ("program_exported", "Returns ExportedProgram"),
            ("device_preserved", "Device placement preserved in export"),
        ],
        requires_same_device=True,  # Model and example inputs same device
        may_raise=["RuntimeError", "ExportBackendSignatureError"],
        docstring="Export a PyTorch module to ExportedProgram",
    ))
    
    # torch.export.save
    registry.register(FunctionContract(
        name="torch.export.save",
        qualname="torch.export.save",
        param_names=["ep", "f", "extra_files", "opset_version"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_exported_program", "ep must be ExportedProgram"),
        ],
        postconditions=[
            ("saved", "ExportedProgram saved to file"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "IOError"],
        docstring="Save ExportedProgram to file",
    ))
    
    # torch.export.load
    registry.register(FunctionContract(
        name="torch.export.load",
        qualname="torch.export.load",
        param_names=["f", "extra_files", "expected_opset_version"],
        param_intervals={},
        return_interval=None,  # Returns ExportedProgram
        preconditions=[
            ("file_exists", "File must exist"),
        ],
        postconditions=[
            ("loaded", "ExportedProgram loaded from file"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "IOError"],
        docstring="Load ExportedProgram from file",
    ))
    
    # torch.export.register_dataclass
    registry.register(FunctionContract(
        name="torch.export.register_dataclass",
        qualname="torch.export.register_dataclass",
        param_names=["cls", "serialized_type_name"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_dataclass", "cls must be a dataclass"),
        ],
        postconditions=[
            ("registered", "Dataclass registered for export"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Register dataclass for export serialization",
    ))
    
    # torch.export.Constraint
    registry.register(ModuleContract(
        name="torch.export.Constraint",
        qualname="torch.export.Constraint",
        init_param_names=["dim", "min", "max"],
        init_param_intervals={
            "min": Interval(0, float('inf')),
            "max": Interval(1, float('inf')),
        },
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("valid_range", "min <= max"),
        ],
        docstring="Constraint for dynamic dimension",
    ))
    
    # torch.export.Dim
    registry.register(FunctionContract(
        name="torch.export.Dim",
        qualname="torch.export.Dim",
        param_names=["name", "min", "max"],
        param_intervals={
            "min": Interval(0, float('inf')),
            "max": Interval(1, float('inf')),
        },
        return_interval=None,  # Returns Dim object
        preconditions=[],
        postconditions=[
            ("dim_created", "Dynamic dimension symbol created"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create dynamic dimension symbol for export",
    ))
    
    # torch.export.dims
    registry.register(FunctionContract(
        name="torch.export.dims",
        qualname="torch.export.dims",
        param_names=["*names"],
        param_intervals={},
        return_interval=None,  # Returns tuple of Dims
        preconditions=[],
        postconditions=[
            ("dims_created", "Multiple dynamic dimension symbols created"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create multiple dynamic dimension symbols",
    ))
    
    # ExportedProgram methods
    registry.register(MethodContract(
        name="torch.export.ExportedProgram.module",
        qualname="torch.export.ExportedProgram.module",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns nn.Module
        preconditions=[],
        postconditions=[
            ("module_returned", "Returns nn.Module for eager execution"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get nn.Module for eager execution",
    ))
    
    registry.register(MethodContract(
        name="torch.export.ExportedProgram.run_decompositions",
        qualname="torch.export.ExportedProgram.run_decompositions",
        param_names=["self", "decomp_table"],
        param_intervals={},
        return_interval=None,  # Returns ExportedProgram
        preconditions=[],
        postconditions=[
            ("decomposed", "Returns decomposed ExportedProgram"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Run decompositions on exported program",
    ))
    
    registry.register(MethodContract(
        name="torch.export.ExportedProgram.validate",
        qualname="torch.export.ExportedProgram.validate",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("validated", "ExportedProgram is valid"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Validate ExportedProgram",
    ))


# ============================================================================
# torch.compile - Dynamo Compilation
# ============================================================================

def _register_compile(registry: ContractRegistry) -> None:
    """Register torch.compile contracts."""
    
    # torch.compile
    registry.register(FunctionContract(
        name="torch.compile",
        qualname="torch.compile",
        param_names=["model", "fullgraph", "dynamic", "backend", "mode",
                    "options", "disable"],
        param_intervals={},
        return_interval=None,  # Returns compiled callable
        preconditions=[
            ("callable", "model must be callable"),
        ],
        postconditions=[
            ("compiled", "Returns compiled version of model"),
            ("device_preserved", "Device placement preserved"),
        ],
        requires_same_device=False,  # Just returns compiled function
        may_raise=["RuntimeError"],
        docstring="Compile a PyTorch model for optimized execution",
    ))
    
    # torch._dynamo.reset
    registry.register(FunctionContract(
        name="torch._dynamo.reset",
        qualname="torch._dynamo.reset",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("reset", "Dynamo cache and state reset"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Reset Dynamo compilation cache",
    ))
    
    # torch._dynamo.explain
    registry.register(FunctionContract(
        name="torch._dynamo.explain",
        qualname="torch._dynamo.explain",
        param_names=["f", "*args", "**kwargs"],
        param_intervals={},
        return_interval=None,  # Returns ExplainOutput
        preconditions=[
            ("callable", "f must be callable"),
        ],
        postconditions=[
            ("explanation", "Returns compilation explanation"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Explain Dynamo compilation for a function",
    ))
    
    # torch._dynamo.optimize
    registry.register(FunctionContract(
        name="torch._dynamo.optimize",
        qualname="torch._dynamo.optimize",
        param_names=["backend", "nopython", "guard_export_fn", "guard_fail_fn",
                    "disable", "dynamic"],
        param_intervals={},
        return_interval=None,  # Returns decorator
        preconditions=[],
        postconditions=[
            ("decorator_returned", "Returns optimization decorator"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Return decorator for Dynamo optimization",
    ))
    
    # torch._dynamo.is_compiling
    registry.register(FunctionContract(
        name="torch._dynamo.is_compiling",
        qualname="torch._dynamo.is_compiling",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("returns_bool", "Returns True if inside Dynamo compilation"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Check if currently inside Dynamo compilation",
    ))
    
    # torch._dynamo.disable
    registry.register(FunctionContract(
        name="torch._dynamo.disable",
        qualname="torch._dynamo.disable",
        param_names=["fn", "recursive"],
        param_intervals={},
        return_interval=None,  # Returns decorated function
        preconditions=[],
        postconditions=[
            ("disabled", "Function will not be compiled"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Disable Dynamo compilation for a function",
    ))
    
    # torch._dynamo.graph_break
    registry.register(FunctionContract(
        name="torch._dynamo.graph_break",
        qualname="torch._dynamo.graph_break",
        param_names=[],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("graph_broken", "Causes graph break in Dynamo"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Force a graph break in Dynamo compilation",
    ))
    
    # torch._dynamo.mark_dynamic
    registry.register(FunctionContract(
        name="torch._dynamo.mark_dynamic",
        qualname="torch._dynamo.mark_dynamic",
        param_names=["t", "index"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_tensor", "t must be a tensor"),
        ],
        postconditions=[
            ("dimension_dynamic", "Dimension marked as dynamic"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark tensor dimension as dynamic",
    ))
    
    # torch._dynamo.mark_static
    registry.register(FunctionContract(
        name="torch._dynamo.mark_static",
        qualname="torch._dynamo.mark_static",
        param_names=["t", "index"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("is_tensor", "t must be a tensor"),
        ],
        postconditions=[
            ("dimension_static", "Dimension marked as static"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Mark tensor dimension as static",
    ))


# ============================================================================
# torch.fx - Graph Manipulation
# ============================================================================

def _register_fx(registry: ContractRegistry) -> None:
    """Register torch.fx contracts."""
    
    # torch.fx.symbolic_trace
    registry.register(FunctionContract(
        name="torch.fx.symbolic_trace",
        qualname="torch.fx.symbolic_trace",
        param_names=["root", "concrete_args", "enable_cpatching"],
        param_intervals={},
        return_interval=None,  # Returns GraphModule
        preconditions=[
            ("traceable", "root must be traceable (no control flow on data)"),
        ],
        postconditions=[
            ("graph_module", "Returns GraphModule with captured graph"),
        ],
        requires_same_device=False,  # Tracing is device-agnostic
        may_raise=["TraceError", "RuntimeError"],
        docstring="Symbolically trace a module to create FX graph",
    ))
    
    # torch.fx.Tracer
    registry.register(ModuleContract(
        name="torch.fx.Tracer",
        qualname="torch.fx.Tracer",
        init_param_names=["autowrap_modules", "autowrap_functions",
                         "param_shapes_constant"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Custom tracer for FX",
    ))
    
    # Tracer.trace
    registry.register(MethodContract(
        name="torch.fx.Tracer.trace",
        qualname="torch.fx.Tracer.trace",
        param_names=["self", "root", "concrete_args"],
        param_intervals={},
        return_interval=None,  # Returns Graph
        preconditions=[],
        postconditions=[
            ("graph_traced", "Returns traced Graph"),
        ],
        requires_same_device=False,
        may_raise=["TraceError"],
        docstring="Trace a module to create Graph",
    ))
    
    # torch.fx.Graph
    registry.register(ModuleContract(
        name="torch.fx.Graph",
        qualname="torch.fx.Graph",
        init_param_names=["owning_module", "tracer_cls", "tracer_extras"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("valid_graph", "Graph is well-formed"),
        ],
        docstring="FX intermediate representation graph",
    ))
    
    # Graph methods
    registry.register(MethodContract(
        name="torch.fx.Graph.create_node",
        qualname="torch.fx.Graph.create_node",
        param_names=["self", "op", "target", "args", "kwargs", "name", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[
            ("valid_op", "op must be valid node op"),
        ],
        postconditions=[
            ("node_created", "Node added to graph"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create a new node in the graph",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.placeholder",
        qualname="torch.fx.Graph.placeholder",
        param_names=["self", "name", "type_expr", "default_value"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("placeholder_created", "Placeholder node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create placeholder (input) node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.get_attr",
        qualname="torch.fx.Graph.get_attr",
        param_names=["self", "qualified_name", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("get_attr_created", "get_attr node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create get_attr node for module attribute",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.call_function",
        qualname="torch.fx.Graph.call_function",
        param_names=["self", "the_function", "args", "kwargs", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("call_function_created", "call_function node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create call_function node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.call_method",
        qualname="torch.fx.Graph.call_method",
        param_names=["self", "method_name", "args", "kwargs", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("call_method_created", "call_method node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create call_method node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.call_module",
        qualname="torch.fx.Graph.call_module",
        param_names=["self", "module_name", "args", "kwargs", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("call_module_created", "call_module node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create call_module node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.output",
        qualname="torch.fx.Graph.output",
        param_names=["self", "result", "type_expr"],
        param_intervals={},
        return_interval=None,  # Returns Node
        preconditions=[],
        postconditions=[
            ("output_created", "Output node added"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Create output node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.erase_node",
        qualname="torch.fx.Graph.erase_node",
        param_names=["self", "to_erase"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("no_users", "Node must have no users"),
        ],
        postconditions=[
            ("node_erased", "Node removed from graph"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Erase a node from the graph",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.inserting_before",
        qualname="torch.fx.Graph.inserting_before",
        param_names=["self", "n"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("context_entered", "Insertion point set before node"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager for inserting nodes before a node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.inserting_after",
        qualname="torch.fx.Graph.inserting_after",
        param_names=["self", "n"],
        param_intervals={},
        return_interval=None,  # Context manager
        preconditions=[],
        postconditions=[
            ("context_entered", "Insertion point set after node"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Context manager for inserting nodes after a node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.lint",
        qualname="torch.fx.Graph.lint",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("linted", "Graph validated for consistency"),
        ],
        requires_same_device=False,
        may_raise=["LintError"],
        docstring="Lint graph for consistency",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Graph.eliminate_dead_code",
        qualname="torch.fx.Graph.eliminate_dead_code",
        param_names=["self", "is_impure_node"],
        param_intervals={},
        return_interval=None,  # Boolean
        preconditions=[],
        postconditions=[
            ("dead_code_removed", "Unused nodes removed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Remove dead code from graph",
    ))
    
    # torch.fx.GraphModule
    registry.register(ModuleContract(
        name="torch.fx.GraphModule",
        qualname="torch.fx.GraphModule",
        init_param_names=["root", "graph", "class_name"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("graph_valid", "Graph is valid"),
            ("code_generated", "Python code generated from graph"),
        ],
        docstring="nn.Module with FX graph representation",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.GraphModule.recompile",
        qualname="torch.fx.GraphModule.recompile",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("recompiled", "forward() regenerated from graph"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Recompile forward() from graph",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.GraphModule.print_readable",
        qualname="torch.fx.GraphModule.print_readable",
        param_names=["self", "print_output"],
        param_intervals={},
        return_interval=None,  # String
        preconditions=[],
        postconditions=[
            ("readable_printed", "Human-readable graph printed"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Print human-readable graph",
    ))
    
    # torch.fx.Node
    registry.register(ModuleContract(
        name="torch.fx.Node",
        qualname="torch.fx.Node",
        init_param_names=["graph", "name", "op", "target", "args", "kwargs",
                         "return_type"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("in_graph", "Node is part of a graph"),
        ],
        docstring="FX graph node",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Node.replace_all_uses_with",
        qualname="torch.fx.Node.replace_all_uses_with",
        param_names=["self", "replace_with", "delete_user_cb", "propagate_meta"],
        param_intervals={},
        return_interval=None,  # List of nodes
        preconditions=[],
        postconditions=[
            ("uses_replaced", "All uses of this node replaced"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Replace all uses of this node with another",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Node.replace_input_with",
        qualname="torch.fx.Node.replace_input_with",
        param_names=["self", "old_input", "new_input"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("input_replaced", "Input replaced in this node"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Replace an input to this node",
    ))
    
    # torch.fx.Interpreter
    registry.register(ModuleContract(
        name="torch.fx.Interpreter",
        qualname="torch.fx.Interpreter",
        init_param_names=["module", "garbage_collect_values"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=True,
        forward_preserves_device=True,
        state_invariants=[
            ("module_set", "GraphModule is set"),
        ],
        docstring="FX graph interpreter for execution/transformation",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Interpreter.run",
        qualname="torch.fx.Interpreter.run",
        param_names=["self", "*args", "initial_env", "enable_io_processing"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("graph_executed", "Graph executed with inputs"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Execute the graph with given inputs",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Interpreter.boxed_run",
        qualname="torch.fx.Interpreter.boxed_run",
        param_names=["self", "args_list"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("boxed_executed", "Graph executed with boxed args"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Execute graph with args as mutable list",
    ))
    
    # torch.fx.Transformer
    registry.register(ModuleContract(
        name="torch.fx.Transformer",
        qualname="torch.fx.Transformer",
        init_param_names=["module"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("module_set", "GraphModule is set"),
        ],
        docstring="FX graph transformer for rewriting graphs",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.Transformer.transform",
        qualname="torch.fx.Transformer.transform",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns GraphModule
        preconditions=[],
        postconditions=[
            ("graph_transformed", "Returns transformed GraphModule"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Transform the graph and return new GraphModule",
    ))
    
    # Proxy
    registry.register(ModuleContract(
        name="torch.fx.Proxy",
        qualname="torch.fx.Proxy",
        init_param_names=["node", "tracer"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("node_set", "Proxy wraps a graph node"),
        ],
        docstring="Proxy object for tracing operations",
    ))


# ============================================================================
# torch.fx.passes - Graph Passes
# ============================================================================

def _register_fx_passes(registry: ContractRegistry) -> None:
    """Register FX graph pass contracts."""
    
    # torch.fx.passes.shape_prop.ShapeProp
    registry.register(ModuleContract(
        name="torch.fx.passes.shape_prop.ShapeProp",
        qualname="torch.fx.passes.shape_prop.ShapeProp",
        init_param_names=["gm", "fake_mode"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("graph_module_set", "GraphModule is set"),
        ],
        docstring="Shape propagation pass",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.passes.shape_prop.ShapeProp.propagate",
        qualname="torch.fx.passes.shape_prop.ShapeProp.propagate",
        param_names=["self", "*args"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("shapes_propagated", "Shape info added to graph nodes"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Propagate shapes through graph",
    ))
    
    # torch.fx.passes.split_module
    registry.register(FunctionContract(
        name="torch.fx.passes.split_module",
        qualname="torch.fx.passes.split_module",
        param_names=["m", "root_m", "split_callback", "qualname_map",
                    "keep_original_order", "keep_original_node_name"],
        param_intervals={},
        return_interval=None,  # Returns GraphModule
        preconditions=[
            ("valid_callback", "split_callback must return partition names"),
        ],
        postconditions=[
            ("module_split", "Module split into submodules"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Split GraphModule into submodules",
    ))
    
    # torch.fx.passes.graph_drawer.FxGraphDrawer
    registry.register(ModuleContract(
        name="torch.fx.passes.graph_drawer.FxGraphDrawer",
        qualname="torch.fx.passes.graph_drawer.FxGraphDrawer",
        init_param_names=["graph_module", "name", "ignore_getattr",
                         "ignore_parameters_and_buffers", "skip_node_names_in_args"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Draw FX graph for visualization",
    ))
    
    registry.register(MethodContract(
        name="torch.fx.passes.graph_drawer.FxGraphDrawer.get_dot_graph",
        qualname="torch.fx.passes.graph_drawer.FxGraphDrawer.get_dot_graph",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns pydot graph
        preconditions=[],
        postconditions=[
            ("dot_returned", "Returns pydot Graph object"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get pydot graph representation",
    ))


# ============================================================================
# torch._inductor - Inductor Compiler
# ============================================================================

def _register_inductor(registry: ContractRegistry) -> None:
    """Register inductor compiler contracts."""
    
    # torch._inductor.config (various settings)
    registry.register(PropertyContract(
        name="torch._inductor.config.debug",
        qualname="torch._inductor.config.debug",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns debug setting"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("debug_set", "Debug mode updated"),
        ],
        docstring="Enable inductor debug mode",
    ))
    
    registry.register(PropertyContract(
        name="torch._inductor.config.triton.cudagraphs",
        qualname="torch._inductor.config.triton.cudagraphs",
        return_interval=None,  # Boolean
        getter_preconditions=[],
        getter_postconditions=[
            ("returns_bool", "Returns CUDA graphs setting"),
        ],
        setter_preconditions=[],
        setter_postconditions=[
            ("cudagraphs_set", "CUDA graphs mode updated"),
        ],
        docstring="Enable CUDA graphs in Triton",
    ))
    
    # torch._inductor.compile
    registry.register(FunctionContract(
        name="torch._inductor.compile",
        qualname="torch._inductor.compile",
        param_names=["gm", "example_inputs", "options"],
        param_intervals={},
        return_interval=None,  # Returns compiled function
        preconditions=[
            ("valid_graph_module", "gm must be GraphModule"),
        ],
        postconditions=[
            ("compiled", "Returns inductor-compiled function"),
        ],
        requires_same_device=True,
        may_raise=["RuntimeError"],
        docstring="Compile GraphModule with inductor",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_export_compile_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.export, torch.compile, and torch.fx contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_export(registry)
    _register_compile(registry)
    _register_fx(registry)
    _register_fx_passes(registry)
    _register_inductor(registry)


# Export
__all__ = [
    "register_export_compile_contracts",
]
