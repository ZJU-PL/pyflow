# Contract Format Specification

## Overview

Contracts model unknown function calls as **over-approximating relations** `R_f ⊆ In × Out`, ensuring soundness: `Sem_f ⊆ R_f`.

This means the contract must allow *at least* all behaviors the actual function may exhibit. It may allow more (false behaviors), but never fewer.

## Soundness Principle

**Critical invariant**: For any contract `R_f`, we must have `Sem_f ⊆ R_f` where:
- `Sem_f` = the actual semantic behavior of function `f`
- `R_f` = the contract (relation) we assume for `f`

Violating this makes the analyzer **unsound** (may report SAFE when bugs exist).

## Default: Havoc Contract

For completely unknown functions, use the **havoc contract**:

```python
Contract.havoc(function_name)
```

This assumes:
- Arbitrary heap reads/writes (`may_read={'*'}`, `may_write={'*'}`)
- May allocate objects
- May raise any exception
- May return any value

The havoc contract is **always sound** because it allows all possible behaviors.

## Contract Structure

```python
@dataclass
class Contract:
    function_name: str
    
    # Over-approximated argument/return constraints
    arg_constraints: List[ValueConstraint]
    return_constraint: ValueConstraint
    
    # Heap footprint
    heap_effect: HeapEffect
    
    # Exception behavior
    exception_effect: ExceptionEffect
    
    # Justification for this contract
    provenance: str  # "default" | "stdlib_spec" | "source_analysis" | "dse_validated"
```

### Heap Effects

```python
@dataclass
class HeapEffect:
    may_read: Set[str]      # Locations that may be read ('*' = anything)
    may_write: Set[str]     # Locations that may be mutated
    may_allocate: bool      # Whether new objects may be allocated
```

Pure functions: `HeapEffect.pure()` (no reads, no writes, no allocation).

### Exception Effects

```python
@dataclass
class ExceptionEffect:
    may_raise: Set[str]     # Exception types ('*' = any exception)
    always_raises: bool     # True if function never returns normally
```

No exceptions: `ExceptionEffect.no_raise()`.

### Value Constraints

```python
@dataclass
class ValueConstraint:
    type_constraint: Optional[str]      # Expected type
    range_constraint: Optional[tuple]   # (min, max) for numerics
    predicate: Optional[str]            # Symbolic predicate (Z3)
```

## Contract Refinement

Contracts can be **refined** (made more precise) if we have **justification**:

1. **From source code**: Analyze the function's implementation
2. **From specification**: Python docs, language reference
3. **From DSE validation**: Observe behaviors and ensure over-approximation

**Never**: Refine based on DSE *failure* to find a behavior (under-approximate oracle).

### Example: Refining `len()`

Start:
```python
Contract.havoc("len")  # Sound but imprecise
```

Refine (justified by Python spec):
```python
Contract(
    function_name="len",
    arg_constraints=[ValueConstraint(type_constraint="object")],
    return_constraint=ValueConstraint(
        type_constraint="int",
        range_constraint=(0, None)  # Non-negative
    ),
    heap_effect=HeapEffect.pure(),  # len() doesn't mutate
    exception_effect=ExceptionEffect(
        may_raise={"TypeError"},     # Only if no __len__
        always_raises=False
    ),
    provenance="stdlib_spec"
)
```

This is sound because Python spec guarantees `len()` behaves this way.

## Provenance Types

- `"default"`: Havoc contract (sound default)
- `"stdlib_spec"`: Justified by Python documentation/specification
- `"source_analysis"`: Analyzed the function's source code
- `"dse_validated"`: Validated behaviors via dynamic execution (with care!)

## Usage in Symbolic Execution

When the symbolic VM encounters an unknown call `f(args)`:

1. Get contract: `contract = get_contract(f_name)`
2. Check contract is sound (not tighter than actual behavior)
3. Apply contract effects:
   - Constrain return value per `return_constraint`
   - Apply `heap_effect` (havoc specified locations)
   - Model `exception_effect` (branch on may_raise)

## Current Stdlib Contracts

We currently have contracts for:
- `len()` - pure, returns non-negative int
- `abs()` - pure, returns non-negative numeric
- `int()` - may allocate, may raise TypeError/ValueError
- `str()` - may read heap (calls `__str__`), may raise anything
- `max()`, `min()` - may read heap (comparison), may raise
- `sum()` - may read heap (iteration), may allocate
- `isinstance()`, `issubclass()` - pure type checks
- `range()` - creates range object, may raise TypeError

## Adding New Contracts

To add a contract:

1. **Ensure soundness**: Over-approximate the actual behavior
2. **Document justification**: Why is this sound?
3. **Register the contract**:
   ```python
   register_contract(Contract(...))
   ```
4. **Test**:
   - Test that contract is retrieved correctly
   - Test that soundness properties hold
   - (Optionally) DSE validation that witnessed behaviors are within contract

## Testing Contracts

Every contract should have tests verifying:
- It can be retrieved
- Its properties match expectations
- It is plausibly sound (conservative)

See `tests/test_contracts.py` for examples.

## Anti-Patterns (Unsound!)

❌ **Never do**:
- Assume a function is pure without justification
- Use DSE failure to shrink `may_raise` or `may_write` sets
- Hardcode behaviors for specific repos/tests
- Copy contracts from comments/docstrings without validation

✅ **Always do**:
- Start with havoc
- Only refine with clear justification
- Document provenance
- Test soundness properties
