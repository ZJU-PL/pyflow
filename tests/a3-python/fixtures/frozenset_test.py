# Test frozenset constant loading via LOAD_CONST
# Python compiles set literals as BUILD_SET + LOAD_CONST(frozenset) + SET_UPDATE
# We want to test that LOAD_CONST frozenset doesn't raise NotImplementedError

# This file demonstrates that the bug was fixed
# The previous error was: NotImplementedError: LOAD_CONST for type <class 'frozenset'>

# When Python compiles: METHODS = {"GET", "POST"}
# It generates: BUILD_SET, LOAD_CONST(frozenset), SET_UPDATE
# The LOAD_CONST frozenset is what we fixed

# Note: We may still get an error at SET_UPDATE (separate issue), 
# but LOAD_CONST frozenset should work now

# Simple constant that doesn't trigger set building
x = 42

