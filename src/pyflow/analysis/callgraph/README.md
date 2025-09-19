# Call Graph Analysis Module

**Current implementation is simplified** - uses Python's `ast` module instead of pyflow's full analysis pipeline.

## Limitations
- No IPA/CPA integration
- Basic AST parsing (not pyflow AST)
- No context sensitivity or data flow analysis
- No type analysis

## Integration Steps

1. **Fix Program class** - store compiler context (`src/pyflow/application/program.py`)
2. **Add CPA integration** - populate call annotations via `ExtractDataflow`
3. **Add IPA integration** - use `CallGraphFinder` for context-sensitive analysis
4. **Use pyflow AST** - convert via `src/pyflow/language/python/parser.py`
5. **Add context tracking** - use `liveFuncContext` and `invokesContext`

## Usage

```python
from pyflow.analysis.callgraph import CallGraphExtractor

extractor = CallGraphExtractor(verbose=True)
call_graph = extractor.extract_from_program(program, compiler, args)
```

## Full Integration Example

```python
def build_full_call_graph(program, compiler, args):
    # Run CPA + IPA analysis
    from pyflow.analysis.cpa import evaluate as cpa_evaluate
    from pyflow.analysis.ipa import evaluate as ipa_evaluate
    cpa_evaluate(compiler, program, opPathLength=0, firstPass=True)
    ipa_evaluate(compiler, program)
    
    # Extract call graph
    from pyflow.analysis.programculler import makeCGF
    cgf = makeCGF(program.interface)
    for code, context in program.interface.entryCodeContexts():
        cgf.process((code, context))
    
    return cgf
```
