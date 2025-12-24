"""
Makefile DSL for PyFlow program configuration.

This module provides a domain-specific language (DSL) for configuring PyFlow
analysis runs. The Makefile class allows users to declare:
- Module to analyze
- Entry points (functions/methods)
- Configuration options
- Output directory

**Makefile DSL Syntax:**
```python
module("mymodule")
output("results/")
entryPoint("myfunction")
config(checkTypes=True)
```

**Usage:**
The Makefile is executed as Python code, with special DSL functions
available in the execution context. After execution, pyflowCompile()
runs the analysis pipeline.
"""
import sys
import os.path

from pyflow.frontend.programextractor import extractProgram
import pyflow.application.pipeline as pipeline
from pyflow.util.application.console import Console

from pyflow.application import context
from pyflow.application.program import Program

from . import interface


def importDeep(name):
    mod = __import__(name)
    components = name.split(".")
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


class Makefile(object):
    """
    Makefile DSL processor for PyFlow configuration.
    
    This class processes a makefile (Python DSL script) that configures
    a PyFlow analysis run. It provides methods for declaring modules,
    entry points, configuration options, and output directories.
    
    **Makefile Structure:**
    - Module declaration: Which Python module to analyze
    - Output directory: Where to write analysis results
    - Entry points: Functions/methods to start analysis from
    - Configuration: Analysis options (type checking, etc.)
    
    **Execution Flow:**
    1. executeFile(): Executes the makefile DSL script
    2. pyflowCompile(): Runs the analysis pipeline on the configured program
    
    Attributes:
        filename: Path to the makefile script
        moduleName: Name of the module to analyze
        module: Imported module object
        workingdir: Working directory (based on makefile location)
        outdir: Output directory for results
        config: Configuration dictionary
        interface: Program interface (set during compilation)
    """
    def __init__(self, filename):
        """
        Initialize a Makefile processor.
        
        Args:
            filename: Path to the makefile script
        """
        self.filename = os.path.normpath(filename)

        self.moduleName = None
        self.module = None

        self.workingdir = os.path.dirname(os.path.join(sys.path[0], self.filename))
        self.outdir = None

        self.config = {}
        self.config["checkTypes"] = False

    def declModule(self, name):
        self.moduleName = name
        self.module = importDeep(name)

    def declOutput(self, path):
        self.outdir = os.path.normpath(os.path.join(self.workingdir, path))

    def declConst(self, value):
        return interface.ExistingWrapper(value)

    def declInstance(self, typename):
        return interface.InstanceWrapper(typename)

    def declConfig(self, **kargs):
        for k, v in kargs.items():
            self.config[k] = v

    def declFunction(self, func, *args):
        self.interface.func.append((func, args))

    def declClass(self, cls):
        assert isinstance(cls, type), cls
        wrapped = interface.ClassDeclaration(cls)
        self.interface.cls.append(wrapped)
        return wrapped

    def declEntryPoint(self, func, *args):
        # Get the function from the module
        # Handle both string names and function objects
        if isinstance(func, str):
            if hasattr(self.module, func):
                func_obj = getattr(self.module, func)
                self.interface.func.append((func_obj, args))
            else:
                # Handle nested attributes like os.path.exists
                parts = func.split(".")
                obj = self.module
                for part in parts:
                    obj = getattr(obj, part)
                self.interface.func.append((obj, args))
        else:
            # func is already a function object, use it directly
            self.interface.func.append((func, args))

    def executeFile(self):
        """
        Execute the makefile DSL script.
        
        Reads the makefile and executes it in a context with DSL functions:
        - module(name): Declare module to analyze
        - output(path): Declare output directory
        - config(**kwargs): Set configuration options
        - const(value): Create constant argument wrapper
        - inst(typename): Create instance argument wrapper
        - func(func, *args): Declare function to analyze
        - cls(class): Declare class to analyze
        - entryPoint(func, *args): Declare entry point
        - attrslot(...): Declare attribute slot (stub)
        - arrayslot(...): Declare array slot (stub)
        
        The makefile is executed as Python code with these functions
        available in the global namespace.
        """
        makeDSL = {
            # Meta declarations
            "module": self.declModule,
            "output": self.declOutput,
            "config": self.declConfig,
            # Argument declarations
            "const": self.declConst,
            "inst": self.declInstance,
            # Interface declarations
            "func": self.declFunction,
            "cls": self.declClass,
            "entryPoint": self.declEntryPoint,
            # Attribute declarations
            "attrslot": interface.AttrDeclaration,
            "arrayslot": interface.ArrayDeclaration,
        }

        f = open(self.filename)
        exec(compile(f.read(), self.filename, "exec"), makeDSL)

    def pyflowCompile(self):
        """
        Run PyFlow analysis on the configured program.
        
        This method:
        1. Creates compiler context and program
        2. Executes the makefile to configure the program
        3. Extracts the program (builds IR, call graph, etc.)
        4. Runs the analysis pipeline
        
        **Prerequisites:**
        - Module must be declared (via declModule)
        - Output directory must be declared (via declOutput)
        - At least one entry point must be declared
        
        Raises:
            AssertionError: If output directory not declared
        """
        compiler = context.CompilerContext(Console())
        prgm = Program()

        self.interface = prgm.interface

        with compiler.console.scope("makefile"):
            compiler.console.output("Processing %s" % self.filename)
            self.executeFile()

            if not self.interface:
                compiler.console.output("No entry points, nothing to do.")
                return

            assert self.outdir, "No output directory declared."

        extractProgram(compiler, prgm)

        pipeline.evaluate(compiler, prgm, self.moduleName)
