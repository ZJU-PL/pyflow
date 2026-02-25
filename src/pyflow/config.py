# usePsyco was a flag for the Psyco JIT compiler, which was only available
# for CPython 2.x and has been unmaintained since ~2012.  It is kept here
# as a no-op boolean so that any code that reads this flag does not break,
# but it has no effect on Python 3.
usePsyco = False

debugOnFailiure = False

# Create output directory relative to this config file.
import os.path

base, junk = os.path.split(__file__)
outputDirectory = os.path.normpath(os.path.join(base, "..", "..", "tmp", "summaries"))

doDump = False
maskDumpErrors = False
doThreadCleanup = False

dumpStats = False


# Pointer analysis testing
useXTypes = True
useControlSensitivity = True
useCPA = True
