"""
Code generation utilities for AST node metaclass.

This module provides functions for generating Python code strings that
implement AST node methods (__init__, __repr__, visit methods, etc.)
and compiling them into executable functions.
"""


def compileFunc(clsname, s, g=None):
    """Compile a function from generated code string.

    Compiles and executes a code string, expecting exactly one function
    to be defined, which is then returned.

    Args:
        clsname: Class name (used for error messages).
        s: Python code string containing function definition.
        g: Global namespace dictionary (default: None).

    Returns:
        Compiled function object.

    Raises:
        AssertionError: If code does not define exactly one function.
    """
    l = {}
    eval(compile(s, "<metaast - %s>" % clsname, "exec"), g, l)
    assert len(l) == 1
    return list(l.values())[0]


def typeName(types):
    """Convert type specification to string representation.

    Converts a type specification (string, tuple, or type object) to a
    string suitable for use in generated type checking code.

    Args:
        types: Type specification (str, tuple/list of types, or type object).

    Returns:
        String representation of the type(s).
    """
    if isinstance(types, str):
        return types
    elif isinstance(types, (tuple, list)):
        return "(%s)" % "".join(["%s," % typeName(t) for t in types])
    elif isinstance(types, type):
        return types.__name__


def makeTypecheck(target, tn, optional):
    """Generate type checking expression.

    Creates a Python expression string that checks if a target value
    matches the expected type.

    Args:
        target: Variable name to check.
        tn: Type name string.
        optional: If True, allow None values.

    Returns:
        String containing type check expression.
    """
    t = "not isinstance(%s, %s)" % (target, tn)
    if optional:
        t = "%s is not None and %s" % (target, t)
    return t


def raiseTypeError(nodeName, typeName, fieldName, fieldSource):
    """Generate TypeError raising code.

    Creates code that raises a TypeError with a descriptive message
    about type mismatch.

    Args:
        nodeName: Name of the AST node class.
        typeName: Expected type name.
        fieldName: Name of the field with type mismatch.
        fieldSource: Variable name containing the invalid value.

    Returns:
        String containing raise statement.
    """
    # Ensure properly closed parentheses in generated code
    return (
        'raise TypeError("Expected %s for field %s.%s, but got %%s instead." %% (%s.__class__.__name__))'
        % (str(typeName), nodeName, fieldName, fieldSource)
    )


def makeScalarTypecheckStatement(
    name, fieldName, fieldSource, tn, optional, tabs, output
):
    """Generate type check statement for a scalar value.

    Appends code to check if a scalar value matches the expected type.

    Args:
        name: AST node class name.
        fieldName: Field name (for error messages).
        fieldSource: Variable name to check.
        tn: Type name string.
        optional: If True, allow None values.
        tabs: Indentation string.
        output: List to append generated code lines to.
    """
    t = makeTypecheck(fieldSource, tn, optional)
    r = raiseTypeError(name, tn, fieldName, fieldSource)
    output.append("%sif %s: %s\n" % (tabs, t, r))


def makeTypecheckStatement(name, field, tn, optional, repeated, tabs, output):
    """Generate type check statement for a field.

    Generates code to validate field type, handling both scalar and
    repeated (list/tuple) fields.

    Args:
        name: AST node class name.
        field: Field descriptor object.
        tn: Type name string.
        optional: If True, allow None values.
        repeated: If True, field is a list/tuple.
        tabs: Indentation string.
        output: List to append generated code lines to.
    """
    if repeated:
        # Check that it's a list/tuple, then check each element
        output.append("%sif isinstance(%s, (list, tuple)):\n" % (tabs, field))
        output.append("%s\tfor _i in %s:\n" % (tabs, field))
        makeScalarTypecheckStatement(
            name, field + "[]", "_i", tn, optional, tabs + "\t\t", output
        )
        # Also allow SymbolBase for symbolic matching
        output.append("%selif not isinstance(%s, SymbolBase):\n" % (tabs, field))
        output.append(
            "%s\t%s\n"
            % (tabs, raiseTypeError(name, "(list, tuple, SymbolBase)", field, field))
        )
    else:
        # Scalar field - check directly
        makeScalarTypecheckStatement(name, field, field, tn, optional, tabs, output)


def makeInitStatements(clsname, desc, dopostinit):
    """Generate initialization statements for __init__ method.

    Creates code to validate and assign field values, and optionally
    call __postinit__.

    Args:
        clsname: AST node class name.
        desc: List of field descriptors.
        dopostinit: If True, call __postinit__ after initialization.

    Returns:
        List of code strings for initialization.
    """
    inits = []
    for field in desc:
        if field.type:
            # Generate type checking code
            tn = typeName(field.type)
            makeTypecheckStatement(
                clsname, field.name, tn, field.optional, field.repeated, "\t", inits
            )
        elif not field.optional:
            # Non-optional field without type - just check for None
            inits.append(
                '\tassert %s is not None, "Field %s.%s is not optional."\n'
                % (field.name, clsname, field.name)
            )

        # Assign field value
        inits.append("\tself.%s = %s\n" % (field.internalname, field.name))

    if dopostinit:
        inits.append("\tself.__postinit__()\n")

    return inits


def argsFromDesc(desc):
    """Generate function argument list from field descriptors.

    Args:
        desc: List of field descriptors.

    Returns:
        String containing function arguments (e.g., "self, x, y").
    """
    if desc:
        fieldstr = ", ".join([field.name for field in desc])
        args = ", ".join(("self", fieldstr))
    else:
        args = "self"
    return args


def makeBody(code):
    """Create function body, using 'pass' if code is empty.

    Args:
        code: Function body code string.

    Returns:
        Code string, or "\tpass\n" if input is empty.
    """
    if not code:
        return "\tpass\n"
    else:
        return code


def makeInit(name, desc, dopostinit):
    """Generate __init__ method code.

    Creates the complete __init__ method code string for an AST node class.

    Args:
        name: AST node class name.
        desc: List of field descriptors.
        dopostinit: If True, call __postinit__ after initialization.

    Returns:
        String containing complete __init__ method definition.
    """
    inits = makeInitStatements(name, desc, dopostinit)
    inits.append("\tself.annotation = self.__emptyAnnotation__")

    args = argsFromDesc(desc)

    # NOTE: super.__init__ should be a no-op, as we're initializing all the fields, anyways?
    # code = "def __init__(%s):\n\tsuper(%s, self).__init__()\n%s" % (args, name, ''.join(inits))
    code = "def __init__(%s):\n%s" % (args, "".join(inits))
    return code


def makeReplaceChildren(name, desc, dopostinit):
    """Generate _replaceChildren method code.

    Creates code for the internal method that replaces children fields
    without creating a new node (for mutable nodes).

    Args:
        name: AST node class name.
        desc: List of field descriptors.
        dopostinit: If True, call __postinit__ after replacement.

    Returns:
        String containing _replaceChildren method definition.
    """
    inits = makeInitStatements(name, desc, dopostinit)

    args = argsFromDesc(desc)

    body = makeBody("".join(inits))

    code = "def _replaceChildren(%s):\n%s" % (args, body)
    return code


def makeRepr(name, desc):
    """Generate __repr__ method code for non-shared nodes.

    Creates a __repr__ method that shows the node type and all field values.

    Args:
        name: AST node class name.
        desc: List of field descriptors.

    Returns:
        String containing __repr__ method definition.
    """
    interp = ", ".join(["%r"] * len(desc))
    fields = " ".join("self.%s," % field.internalname for field in desc)

    code = """def __repr__(self):
    return "%s(%s)" %% (%s)
""" % (
        name,
        interp,
        fields,
    )

    return code


def makeSharedRepr(name, desc):
    """Generate __repr__ method code for shared nodes.

    Creates a __repr__ method that only shows the node type and object ID.
    This prevents recursion when printing shared nodes that may contain
    circular references.

    Args:
        name: AST node class name.
        desc: List of field descriptors (unused, but kept for consistency).

    Returns:
        String containing __repr__ method definition.
    """
    code = """def __repr__(self):
    return "%s(%%d)" %% (id(self),)
""" % (
        name
    )

    return code


def makeAccept(name):
    """Generate accept method code for visitor pattern.

    Creates an accept method that dispatches to the appropriate visitor
    method based on the node type.

    Args:
        name: AST node class name.

    Returns:
        String containing accept method definition.
    """
    code = """def accept(self, visitor, *args):
    return visitor.visit%s(self, *args)
""" % (
        name
    )

    return code


def makeGetChildren(desc):
    """Generate children method code.

    Creates a method that returns a tuple of all child field values.

    Args:
        desc: List of field descriptors.

    Returns:
        String containing children method definition.
    """
    children = " ".join(["self.%s," % field.internalname for field in desc])
    code = """def children(self):
    return (%s)
""" % (
        children
    )

    return code


def makeGetFields(desc):
    """Generate fields method code.

    Creates a method that returns a tuple of (name, value) pairs for
    all fields.

    Args:
        desc: List of field descriptors.

    Returns:
        String containing fields method definition.
    """
    children = " ".join(
        ["(%r, self.%s)," % (field.name, field.internalname) for field in desc]
    )
    code = """def fields(self):
    return (%s)
""" % (
        children
    )

    return code


def makeSetter(clsname, field):
    """Generate property setter method code.

    Creates a setter method with type checking for a field property.

    Args:
        clsname: AST node class name.
        field: Field descriptor.

    Returns:
        String containing setter method definition.
    """
    inits = []

    tn = typeName(field.type)
    makeTypecheckStatement(
        clsname, field.name, tn, field.optional, field.repeated, "\t", inits
    )
    inits.append("\tself.%s = %s\n" % (field.internalname, field.name))

    code = "def __set_%s__(self, %s):\n%s" % (field.name, field.name, "".join(inits))
    return code


def makeGetter(clsname, desc):
    """Generate property getter method code.

    Creates a getter method for a field property.

    Args:
        clsname: AST node class name (unused, kept for consistency).
        desc: Field descriptor.

    Returns:
        String containing getter method definition.
    """
    code = "def __get_%s__(self):\n\treturn self.%s\n" % (desc.name, desc.internalname)
    return code


def makeVisit(
    clsname, desc, reverse=False, shared=False, forced=False, vargs=False, kargs=False
):
    """Generate visitChildren method code.

    Creates a method that visits all child nodes, calling a callback
    function for each. Supports various options for traversal order and
    argument passing.

    Args:
        clsname: AST node class name (unused, kept for consistency).
        desc: List of field descriptors.
        reverse: If True, visit children in reverse order.
        shared: If True, node is shared (may skip visiting if not forced).
        forced: If True, visit even if node is shared.
        vargs: If True, accept *vargs in callback.
        kargs: If True, accept **kargs in callback.

    Returns:
        String containing visitChildren method definition.
    """
    args = "self, _callback"

    additionalargs = ""
    if vargs:
        additionalargs += ", *vargs"
    if kargs:
        additionalargs += ", **kargs"
    args += additionalargs

    statements = []

    # Shared nodes skip visiting unless forced
    if not shared or forced:
        iterator = reversed(desc) if reverse else desc

        for field in iterator:
            indent = "\t"

            # Handle optional fields
            if field.optional:
                statements.append(
                    "%sif self.%s is not None:\n" % (indent, field.internalname)
                )
                indent += "\t"

            # Handle repeated fields (lists/tuples)
            if field.repeated:
                if reverse:
                    statements.append(
                        "%sfor _child in reversed(self.%s):\n"
                        % (indent, field.internalname)
                    )
                else:
                    statements.append(
                        "%sfor _child in self.%s:\n" % (indent, field.internalname)
                    )
                indent += "\t"
                src = "_child"
            else:
                src = "self." + field.internalname

            statements.append("%s_callback(%s%s)\n" % (indent, src, additionalargs))

    body = makeBody("".join(statements))

    funcname = "visitChildren"
    if reverse:
        funcname += "Reversed"

    if forced:
        funcname += "Forced"

    code = "def %s(%s):\n%s" % (funcname, args, body)

    return code


def makeRewrite(
    clsname,
    desc,
    reverse=False,
    mutate=False,
    shared=False,
    forced=False,
    vargs=False,
    kargs=False,
):
    """Generate rewriteChildren or replaceChildren method code.

    Creates a method that applies a callback to all children and either
    creates a new node (rewrite) or modifies the current node (replace).
    Handles shared nodes, optional fields, repeated fields, and symbolic
    matching.

    Args:
        clsname: AST node class name.
        desc: List of field descriptors.
        reverse: If True, process children in reverse order.
        mutate: If True, modify node in place (replaceChildren).
        shared: If True, node is shared.
        forced: If True, rewrite even if node is shared.
        vargs: If True, accept *vargs in callback.
        kargs: If True, accept **kargs in callback.

    Returns:
        String containing rewriteChildren or replaceChildren method definition.

    Raises:
        AssertionError: If invalid combination of parameters is provided.
    """
    assert not (mutate and forced), clsname
    assert not forced or shared, clsname

    args = "self, _callback"

    statements = []

    additionalargs = ""
    if vargs:
        additionalargs += ", *vargs"
    if kargs:
        additionalargs += ", **kargs"
    args += additionalargs

    # Shared nodes skip rewriting unless mutating or forced
    if not shared or mutate or forced:
        iterator = reversed(desc) if reverse else desc

        uid = 0
        targets = []
        mutation = []

        for field in iterator:
            target = "_%d" % uid
            uid += 1
            targets.append(target)

            if field.repeated:
                # Handle list/tuple fields
                childexpr = "_callback(_child%s)" % (additionalargs,)
                if field.optional:
                    childexpr += " if _child is not None else None"

                if reverse:
                    expr = "list(reversed([%s for _child in reversed(self.%s)]))" % (
                        childexpr,
                        field.internalname,
                    )
                else:
                    expr = "[%s for _child in self.%s]" % (
                        childexpr,
                        field.internalname,
                    )

                # Guard against symbols - if field is a SymbolBase, call callback directly
                expr = (
                    "_callback(self.%s%s) if isinstance(self.%s, SymbolBase) else %s"
                    % (field.internalname, additionalargs, field.internalname, expr)
                )
            else:
                # Handle scalar fields
                expr = "_callback(self.%s%s)" % (field.internalname, additionalargs)

                if field.optional:
                    expr += " if self.%s is not None else None" % field.internalname

            statements.append("\t%s = %s\n" % (target, expr))

            if mutate:
                mutation.append("\tself.%s = %s\n" % (field.internalname, target))

        if mutate:
            # In-place mutation
            statements.extend(mutation)
            statements.append("\treturn self\n")
        else:
            # Create new node
            if reverse:
                targets.reverse()

            statements.append("\tresult = %s(%s)\n" % (clsname, ", ".join(targets)))
            statements.append("\tresult.annotation = self.annotation\n")
            statements.append("\treturn result\n")
    else:
        # Rewriting a shared node without mutation or forcing - do nothing
        statements.append("\treturn self\n")

    body = makeBody("".join(statements))

    funcname = "replaceChildren" if mutate else "rewriteChildren"

    if reverse:
        funcname += "Reversed"

    if forced:
        funcname += "Forced"

    code = "def %s(%s):\n%s" % (funcname, args, body)

    return code
