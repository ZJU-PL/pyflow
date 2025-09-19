# @PydevCodeAnalysisIgnore

module("math")
output("../temp")

# Test basic math functions
entryPoint("sqrt", const(16.0))
entryPoint("sin", const(0.0))
entryPoint("cos", const(0.0))
entryPoint("log", const(2.71828))
entryPoint("exp", const(1.0))
entryPoint("pow", const(2.0), const(3.0))
entryPoint("ceil", const(3.2))
entryPoint("floor", const(3.8))
entryPoint("fabs", const(-5.0))
entryPoint("factorial", const(5))
