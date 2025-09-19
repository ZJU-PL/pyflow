import time
import importlib.util
from pyflow.application.makefile import Makefile

compileCache = {}
loadCache = {}


def compileExample(filename):
    # Done in two phases, as the compilation can
    # succeed but generate bogus code, which prevents import.
    # Compiling multiple times may be problematic, as globals are used.
    if not filename in compileCache:
        make = Makefile(filename)

        start = time.perf_counter()
        make.pyflowCompile()
        end = time.perf_counter()

        if True:
            print("Compile time: %.3f sec" % (end - start))

        compileCache[filename] = make

    return None, None  # HACK prevents further compilation

    if not filename in loadCache:
        make = compileCache[filename]

        module = make.module

        # HACK mangle the module name
        spec = importlib.util.spec_from_file_location(
            make.moduleName + "gen", make.outfile
        )
        generated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generated)

        loadCache[filename] = (module, generated)

    return loadCache[filename]
