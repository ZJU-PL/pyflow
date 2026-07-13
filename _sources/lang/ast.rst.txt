AST for Python
===============

PyFlow's Abstract Syntax Tree (AST) is the core intermediate representation used throughout the analysis pipeline. It provides a semantically-aware representation of Python code designed for static analysis and optimization.

===============
Overview
===============

The AST module (`pyflow.language.python.ast`) defines all node types for representing Python programs. Unlike Python's standard AST, PyFlow's AST is designed specifically for static analysis.

**Key Design Principles:**
  - Semantic preservation of Python semantics
  - Analysis-friendly structure
  - Annotation support for context-sensitive metadata
  - Transformable (clone, rewrite, transform)
  - Type-safe with dispatch for visitor patterns

**Node Hierarchy:**
  - ``PythonASTNode`` - Root of all AST nodes
  - ``Expression`` - Nodes that compute values
  - ``Statement`` - Nodes that perform actions
  - ``Reference`` - Nodes that reference values
  - ``ControlFlow`` - Control flow statements
  - ``BaseCode`` - Function and method definitions

===============
Reference Nodes
===============

**Existing**: Represents constant Python objects (literals, constants)

.. code-block:: python

   from pyflow.language.python import ast
   from pyflow.language.python.program import Object
   
   const = ast.Existing(Object(42))
   # Properties: object, isPure(), constantValue()

**Local**: Represents local variables or function parameters

.. code-block:: python

   local = ast.Local("x")  # name can be None for anonymous
   # Properties: name, isPure()
   # Important: Local nodes are shared (same object = same variable)

**DoNotCare**: Wildcard value for pattern matching

.. code-block:: python

   wildcard = ast.DoNotCare()

===============
Expression Nodes
===============

**Call**: Function call with dynamic dispatch

.. code-block:: python

   call = ast.Call(expr=func_expr, args=[arg1], kwds=[], vargs=None, kargs=None)

**DirectCall**: Direct call to known function (created by optimization)

.. code-block:: python

   direct = ast.DirectCall(code=func_code, selfarg=None, args=[arg1], kwds=[], vargs=None, kargs=None)

**MethodCall**: Method call with known method name

.. code-block:: python

   method = ast.MethodCall(expr=obj_expr, name=name_expr, args=[arg1], kwds=[], vargs=None, kargs=None)

**BinaryOp / UnaryPrefixOp**: Arithmetic and logical operations

.. code-block:: python

   add = ast.BinaryOp(left=left_expr, op="+", right=right_expr)
   neg = ast.UnaryPrefixOp(op="-", expr=expr)
   # Operators: +, -, *, /, //, %, **, &, |, ^, <<, >>, ==, !=, <, <=, >, >=

**GetAttr / SetAttr**: Attribute access and modification

.. code-block:: python

   get_attr = ast.GetAttr(expr=obj_expr, name=name_expr)
   set_attr = ast.SetAttr(value=value_expr, expr=obj_expr, name=name_expr)

**GetSubscript / SetSubscript**: Indexing operations

.. code-block:: python

   get_sub = ast.GetSubscript(expr=obj_expr, subscript=index_expr)
   set_sub = ast.SetSubscript(value=value_expr, expr=obj_expr, subscript=index_expr)

**Container Construction**: ``BuildTuple([expr1, expr2])``, ``BuildList([expr1, expr2])``, ``BuildMap()``

===============
Statement Nodes
===============

**Assign**: Variable assignment (supports multiple assignment)

.. code-block:: python

   assign = ast.Assign(expr=value_expr, lcls=[local1, local2])

**Return**: Function return (Python allows multiple returns)

.. code-block:: python

   return_node = ast.Return([expr1, expr2])

**Discard**: Expression statement (side effects only)

.. code-block:: python

   discard = ast.Discard(expr)

**Delete**: Variable deletion

.. code-block:: python

   delete = ast.Delete(local)

===============
Control Flow Nodes
===============

**Switch**: Conditional execution (if/else)

.. code-block:: python

   switch = ast.Switch(
       condition=ast.Condition(preamble=ast.Suite([]), conditional=cond_expr),
       t=then_suite,
       f=else_suite
   )

**While**: While loops

.. code-block:: python

   while_loop = ast.While(
       condition=ast.Condition(preamble=ast.Suite([]), conditional=cond_expr),
       body=body_suite,
       else_=else_suite
   )

**For**: For loops

.. code-block:: python

   for_loop = ast.For(
       iterator=iter_expr,
       index=index_local,
       loopPreamble=ast.Suite([]),
       bodyPreamble=ast.Suite([]),
       body=body_suite,
       else_=else_suite
   )

**TryExceptFinally**: Exception handling

.. code-block:: python

   try_node = ast.TryExceptFinally(
       body=try_suite,
       handlers=[ast.ExceptionHandler(preamble=ast.Suite([]), type=exc_type_expr, value=exc_value_local, body=handler_suite)],
       defaultHandler=None,
       else_=else_suite,
       finally_=finally_suite
   )

**Break / Continue**: Loop control statements

.. code-block:: python

   break_node = ast.Break()
   continue_node = ast.Continue()

===============
Code Nodes
===============

**Code**: Function or method definition

.. code-block:: python

   code = ast.Code(
       name="function_name",
       codeparameters=ast.CodeParameters(
           selfparam=None,
           params=[ast.Local("x"), ast.Local("y")],
           paramnames=["x", "y"],
           defaults=[],
           vparam=None,
           kparam=None,
           returnparams=[ast.Local("ret0")]
       ),
       ast=body_suite
   )
   # Properties: name, codeparameters, ast, annotation (CodeAnnotation)

**FunctionDef**: Function definition with decorators

.. code-block:: python

   func_def = ast.FunctionDef(name="function_name", code=code_node, decorators=[decor1])

**ClassDef**: Class definition

.. code-block:: python

   class_def = ast.ClassDef(name="ClassName", bases=[base1], body=body_suite, decorators=[decor1])

===============
Suite and Annotations
===============

**Suite**: Sequence of statements

.. code-block:: python

   suite = ast.Suite([statement1, statement2])
   # Properties: blocks (list of Statement nodes)
   # Methods: append(), insertHead()

**Annotations**: AST nodes carry analysis results via the ``annotation`` attribute

- **CodeAnnotation** (on Code nodes): Context-sensitive results, live variables, read/modify/allocate sets
- **OpAnnotation** (on Expression/Statement nodes): Operation-level results, invocation information
- **SlotAnnotation** (on Reference nodes): Variable reference tracking

===============
Node Properties
===============

Common methods on AST nodes:

**Type Queries**: ``isPure()``, ``returnsValue()``, ``alwaysReturnsBoolean()``, ``isControlFlow()``, ``isReference()``, ``isCode()``

**Traversal**: ``visitChildren(visitor)``, ``visitChildrenReversed(visitor)``, ``visitChildrenForcedArgs(visitor, force)``

**Transformation**: ``clone()``, ``rewrite(**kwargs)``

===============
Usage Examples
===============

Creating a Simple Function
--------------------------

.. code-block:: python

   from pyflow.language.python import ast
   from pyflow.language.python.program import Object
   
   params = ast.CodeParameters(
       selfparam=None,
       params=[ast.Local("x"), ast.Local("y")],
       paramnames=["x", "y"],
       defaults=[],
       vparam=None,
       kparam=None,
       returnparams=[ast.Local("ret0")]
   )
   
   body = ast.Suite([
       ast.Return([
           ast.BinaryOp(left=ast.Local("x"), op="+", right=ast.Local("y"))
       ])
   ])
   
   code = ast.Code("add", params, body)

Creating Control Flow
---------------------

.. code-block:: python

   condition = ast.Condition(
       preamble=ast.Suite([]),
       conditional=ast.BinaryOp(left=ast.Local("x"), op=">", right=ast.Existing(Object(0)))
   )
   
   switch = ast.Switch(
       condition=condition,
       t=ast.Suite([ast.Return([ast.Local("x")])]),
       f=ast.Suite([ast.Return([ast.Existing(Object(0))])])
   )

===============
See Also
===============

- :doc:`frontend` - How Python code is converted to this AST
- :doc:`index` - Language module overview
- :doc:`../analysis/index` - Analysis passes operating on AST
- :doc:`../optimization/index` - Optimizations transforming AST
