# @PydevCodeAnalysisIgnore

module("simple_test")
output("../temp")

# Test simple functions
entryPoint("simple_add", inst("int"), inst("int"))
entryPoint("simple_multiply", inst("float"), inst("float"))
entryPoint("simple_constant")
