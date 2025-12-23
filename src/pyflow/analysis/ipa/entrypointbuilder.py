"""Entry point builder for IPA.

This module builds entry points for inter-procedural analysis by creating
initial contexts and binding entry point arguments.
"""

from pyflow.language.python import ast


def buildTempLocal(analysis, objs):
    """Build a temporary local variable for entry point arguments.
    
    Creates a local variable in the root context and initializes it with
    object names from the entry point arguments.
    
    Args:
        analysis: IPAnalysis instance
        objs: List of ExtendedType objects (or None)
        
    Returns:
        ConstraintNode or None: Local variable node, or None if objs is None
    """
    if objs is None:
        return None
    else:
        lcl = analysis.root.local(ast.Local("entry_point_arg"))
        objs = frozenset([analysis.objectName(xtype) for xtype in objs])
        lcl.updateValues(objs)
        return lcl


def buildEntryPoint(analysis, ep, epargs):
    """Build an entry point for inter-procedural analysis.
    
    Creates entry point arguments as local variables in the root context
    and initiates a direct call to the entry point function.
    
    Args:
        analysis: IPAnalysis instance
        ep: Entry point function object
        epargs: EntryPointArgs containing selfarg, args, vargs, kargs
    """
    selfarg = buildTempLocal(analysis, epargs.selfarg)

    args = []
    for arg in epargs.args:
        args.append(buildTempLocal(analysis, arg))

    varg = buildTempLocal(analysis, epargs.vargs)
    karg = buildTempLocal(analysis, epargs.kargs)

    analysis.root.dcall(ep, ep.code, selfarg, args, [], varg, karg, None)
