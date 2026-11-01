from . import transform, ssa, expandphi, simplify, structuralanalysis


def evaluateCode(compiler, code):
    g = transform.evaluate(compiler, code)

    ssa.evaluate(compiler, g)
    expandphi.evaluate(compiler, g)
    simplify.evaluate(compiler, g)

    try:
        structuralanalysis.evaluate(compiler, g)
    except structuralanalysis.StructuralAnalysisError:
        if not getattr(g, "has_exception_regions", False):
            raise

    return g.code
