import unittest
from pyflow.analysis.ipa.ipanalysis import IPAnalysis
from pyflow.analysis.ipa.constraints import qualifiers
from pyflow.analysis.storegraph.canonicalobjects import CanonicalObjects
from pyflow.language.python import program

from pyflow.application.context import CompilerContext


class MockExtractor(object):
    def __init__(self):
        self.cache = {}

    def getObject(self, pyobj):
        key = (type(pyobj), pyobj)
        result = self.cache.get(key)
        if result is None:
            result = program.Object(pyobj)
            self.cache[key] = result
        return result


class MockSignature(object):
    def __init__(self):
        self.code = None


class TestIPABase(unittest.TestCase):
    def setUp(self):
        self.compiler = CompilerContext(None)
        self.extractor = MockExtractor()
        self.compiler.extractor = self.extractor
        self.canonical = CanonicalObjects()
        existingPolicy = None
        externalPolicy = None

        self.analysis = IPAnalysis(
            self.compiler, self.canonical, existingPolicy, externalPolicy
        )

    def local(self, context, name, *values):
        lcl = context.local(name)
        if values:
            lcl.updateValues(frozenset(values))
        return lcl

    def assertIsInstance(self, obj, cls, msg=None):
        self.assertTrue(isinstance(obj, cls), msg or "expected %r, got %r" % (cls, type(obj)))

    def const(self, pyobj, qualifier=qualifiers.HZ):
        obj = self.extractor.getObject(pyobj)
        xtype = self.canonical.existingType(obj)
        return self.analysis.objectName(xtype, qualifier)

    def makeContext(self):
        return self.analysis.getContext(MockSignature())
