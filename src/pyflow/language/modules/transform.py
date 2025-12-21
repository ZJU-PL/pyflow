"""AST transformation utilities for simplifying Python code structure.

This module provides AST (Abstract Syntax Tree) transformers that normalize
and simplify Python code to make it easier to analyze statically. These
transformations may be used as preprocessing steps in the tatic analysis pipeline.

The module contains several transformer classes that handle different
aspects of code simplification:

1. AsyncTransformer: Converts asynchronous Python constructs (async/await)
   into their synchronous equivalents, eliminating the need to handle
   async semantics during static analysis.

2. ChainedFunctionTransformer: Breaks down chained method calls into
   separate assignment statements with temporary variables. For example,
   converts `x = obj.method1().method2()` into multiple statements that
   are easier to analyze step-by-step.

3. IfExpTransformer/IfExpRewriter: Simplifies complex ternary expressions
   (IfExp) by extracting complex test conditions into separate assignment
   statements. This makes control flow analysis more straightforward.

4. PytTransformer: A composite transformer that applies all of the above transformations in a single pass. 

Example:
    >>> import ast
    >>> from pyflow.language.modules.transform import PytTransformer
    >>> 
    >>> code = '''
    ... async def example():
    ...     return await some_func()
    ... '''
    >>> tree = ast.parse(code)
    >>> transformer = PytTransformer()
    >>> transformed_tree = transformer.visit(tree)
    >>> # The transformed tree now has synchronous code instead of async
"""

import ast


class AsyncTransformer():
    """Converts all async nodes into their synchronous counterparts."""

    def visit_Await(self, node):
        """Awaits are treated as if the keyword was absent."""
        return self.visit(node.value)

    def visit_AsyncFunctionDef(self, node):
        return self.visit(ast.FunctionDef(**node.__dict__))

    def visit_AsyncFor(self, node):
        return self.visit(ast.For(**node.__dict__))

    def visit_AsyncWith(self, node):
        return self.visit(ast.With(**node.__dict__))


class ChainedFunctionTransformer():
    """Transforms chained method calls into separate assignment statements.
    
    Breaks down expressions like `x = obj.method1().method2().method3()` into
    multiple statements using temporary variables. This simplifies analysis by
    making each method call explicit and easier to track.
    
    Example transformation:
        Original: `b = c.d(e).f(g).h(i).j(k)`
        Transformed:
            __chain_tmp_3 = c.d(e)
            __chain_tmp_2 = __chain_tmp_3.f(g)
            __chain_tmp_1 = __chain_tmp_2.h(i)
            b = __chain_tmp_1.j(k)
    """
    
    def visit_chain(self, node, depth=1):
        if (
            isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and
            isinstance(node.value.func.value, ast.Call)
        ):
            # Node is assignment or return with value like `b.c().d()`
            call_node = node.value
            # If we want to handle nested functions in future, depth needs fixing
            temp_var_id = '__chain_tmp_{}'.format(depth)
            # AST tree is from right to left, so d() is the outer Call and b.c() is the inner Call
            unvisited_inner_call = ast.Assign(
                targets=[ast.Name(id=temp_var_id, ctx=ast.Store())],
                value=call_node.func.value,
            )
            ast.copy_location(unvisited_inner_call, node)
            inner_calls = self.visit_chain(unvisited_inner_call, depth + 1)
            for inner_call_node in inner_calls:
                ast.copy_location(inner_call_node, node)
            outer_call = self.generic_visit(type(node)(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id=temp_var_id, ctx=ast.Load()),
                        attr=call_node.func.attr,
                        ctx=ast.Load(),
                    ),
                    args=call_node.args,
                    keywords=call_node.keywords,
                ),
                **{field: value for field, value in ast.iter_fields(node) if field != 'value'}  # e.g. targets
            ))
            ast.copy_location(outer_call, node)
            ast.copy_location(outer_call.value, node)
            ast.copy_location(outer_call.value.func, node)
            return [*inner_calls, outer_call]
        else:
            return [self.generic_visit(node)]

    def visit_Assign(self, node):
        return self.visit_chain(node)

    def visit_Return(self, node):
        return self.visit_chain(node)


class IfExpRewriter(ast.NodeTransformer):
    """Splits IfExp ternary expressions containing complex tests into multiple statements

    Will change

    a if b(c) else d

    into

    a if __if_exp_0 else d

    with Assign nodes in assignments [__if_exp_0 = b(c)]
    """

    def __init__(self, starting_index=0):
        self._temporary_variable_index = starting_index
        self.assignments = []
        super().__init__()

    def visit_IfExp(self, node):
        if isinstance(node.test, (ast.Name, ast.Attribute)):
            return self.generic_visit(node)
        else:
            temp_var_id = '__if_exp_{}'.format(self._temporary_variable_index)
            self._temporary_variable_index += 1
            assignment_of_test = ast.Assign(
                targets=[ast.Name(id=temp_var_id, ctx=ast.Store())],
                value=self.visit(node.test),
            )
            ast.copy_location(assignment_of_test, node)
            self.assignments.append(assignment_of_test)
            transformed_if_exp = ast.IfExp(
                test=ast.Name(id=temp_var_id, ctx=ast.Load()),
                body=self.visit(node.body),
                orelse=self.visit(node.orelse),
            )
            ast.copy_location(transformed_if_exp, node)
            return transformed_if_exp

    def visit_FunctionDef(self, node):
        return node


class IfExpTransformer:
    """Goes through module and function bodies, adding extra Assign nodes due to IfExp expressions."""

    def visit_body(self, nodes):
        new_nodes = []
        count = 0
        for node in nodes:
            rewriter = IfExpRewriter(count)
            possibly_transformed_node = rewriter.visit(node)
            if rewriter.assignments:
                new_nodes.extend(rewriter.assignments)
                count += len(rewriter.assignments)
            new_nodes.append(possibly_transformed_node)
        return new_nodes

    def visit_FunctionDef(self, node):
        # Preserve all fields including Python 3.12+ type_params
        kwargs = {
            'name': node.name,
            'args': node.args,
            'body': self.visit_body(node.body),
            'decorator_list': node.decorator_list,
            'returns': node.returns
        }
        # Include type_params if it exists (Python 3.12+)
        if hasattr(node, 'type_params'):
            kwargs['type_params'] = node.type_params
        transformed = ast.FunctionDef(**kwargs)
        ast.copy_location(transformed, node)
        return self.generic_visit(transformed)

    def visit_Module(self, node):
        # Preserve all fields including Python 3.12+ type_ignores
        kwargs = {'body': self.visit_body(node.body)}
        # Include type_ignores if it exists (Python 3.12+)
        if hasattr(node, 'type_ignores'):
            kwargs['type_ignores'] = node.type_ignores
        transformed = ast.Module(**kwargs)
        ast.copy_location(transformed, node)
        return self.generic_visit(transformed)


class PytTransformer(AsyncTransformer, IfExpTransformer, ChainedFunctionTransformer, ast.NodeTransformer):
    """Composite transformer that applies all AST normalization transformations.
    
    This class combines all individual transformers (AsyncTransformer,
    IfExpTransformer, and ChainedFunctionTransformer) into a single transformer
    that can be applied in one pass. This is the main transformer used
    throughout PyFlow for preprocessing Python ASTs before static analysis.
    
    The transformer applies the following transformations in order:
    1. Async/await constructs are converted to synchronous equivalents
    2. Complex ternary expressions are simplified with extracted conditions
    3. Chained method calls are broken into separate statements
    
    This transformer is typically used in the AST preprocessing stage, before control flow graph construction and other analyses.
    
    See Also:
        generate_ast() in ast_helper.py: Uses this transformer for AST preprocessing
    """
    pass