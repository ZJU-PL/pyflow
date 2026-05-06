# UNINIT_MEMORY Synthetic Test Suite

## Bug Type: UNINIT_MEMORY

**Definition**: Use of a variable or object attribute before it has been assigned a value, leading to `UnboundLocalError` or `AttributeError` at runtime.

**Semantic unsafe region**: A machine state where a name is referenced but not bound in the current namespace (locals/globals/__dict__).

## Test Structure

### True Positives (5 tests - MUST report BUG)

1. **tp_01_variable_used_before_assignment.py**
   - Direct use-before-def: variable referenced without any prior assignment
   - Runtime: `UnboundLocalError`

2. **tp_02_conditional_missing_branch.py**
   - Control-flow sensitive: variable assigned only in if-branch, used after conditional
   - Path exists where variable is never assigned
   - Runtime: `UnboundLocalError` when condition is False

3. **tp_03_loop_conditional_init.py**
   - Loop with conditional assignment: variable only assigned if loop condition matches
   - Uninitialized if loop never executes or condition never matches
   - Runtime: `UnboundLocalError` with empty list or no matches

4. **tp_04_exception_handler_uninitialized.py**
   - Exception path: variable assigned in try block, accessed in except block
   - If exception occurs before assignment, variable is uninitialized
   - Runtime: `UnboundLocalError` in exception handler

5. **tp_05_class_attribute_uninitialized.py**
   - Object attribute: instance attribute conditionally initialized in __init__
   - Method assumes attribute exists but it may not
   - Runtime: `AttributeError`

### True Negatives (5 tests - MUST NOT report BUG)

1. **tn_01_all_paths_assigned.py**
   - Variable assigned in all branches before use
   - All CFG paths have def-before-use

2. **tn_02_default_init_in_constructor.py**
   - Instance attributes always initialized in __init__
   - All attributes guaranteed present after construction

3. **tn_03_default_parameter_init.py**
   - Default parameters and explicit initialization ensure variable is always defined
   - Def-before-use by parameter binding or explicit assignment

4. **tn_04_try_except_both_branches.py**
   - Variable assigned in both try and except branches
   - All exception paths covered

5. **tn_05_loop_default_before_iteration.py**
   - Default value assigned before loop
   - Safe even if loop doesn't execute or finds no matches

## Semantic Model Requirements

To correctly detect UNINIT_MEMORY bugs, the analyzer must:

1. **Track definite assignments**: maintain a set of "definitely assigned" variables for each program point
2. **Handle control flow**: track assignments through branches, loops, and exception handlers
3. **Model exception edges**: consider paths where exceptions interrupt normal flow
4. **Distinguish locals from globals**: respect Python's name resolution (LEGB: Local, Enclosing, Global, Built-in)
5. **Track object attributes**: model __dict__ or equivalent for instance/class attributes

## Expected Analyzer Behavior

- **For true positives**: Report BUG with a witness trace showing a path from entry to use-point where the variable is not assigned
- **For true negatives**: Either report SAFE (with proof that all paths assign before use) or UNKNOWN (if proof generation fails)
- **Never**: Report SAFE on true positives or BUG on true negatives

## Validation

Run each test file and verify:
- True positives crash with UnboundLocalError or AttributeError
- True negatives execute successfully without errors

```bash
# True positives should fail
python tp_01_variable_used_before_assignment.py  # UnboundLocalError
python tp_02_conditional_missing_branch.py       # UnboundLocalError
python tp_03_loop_conditional_init.py            # UnboundLocalError
python tp_04_exception_handler_uninitialized.py  # UnboundLocalError
python tp_05_class_attribute_uninitialized.py    # AttributeError

# True negatives should succeed
python tn_01_all_paths_assigned.py              # OK
python tn_02_default_init_in_constructor.py      # OK
python tn_03_default_parameter_init.py           # OK
python tn_04_try_except_both_branches.py         # OK
python tn_05_loop_default_before_iteration.py    # OK
```
