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
    def __init__(self, filename):
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
