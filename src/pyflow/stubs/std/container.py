# @PydevCodeAnalysisIgnore

from __future__ import absolute_import

from ..stubcollector import stubgenerator

from pyflow.util.monkeypatch import xtypes

tupleiterator = xtypes.TupleIteratorType
listiterator = xtypes.ListIteratorType
rangeiterator = xtypes.XRangeIteratorType


@stubgenerator
def makeContainerStubs(collector):
    replaceAttr = collector.replaceAttr

    llfunc = collector.llfunc
    export = collector.export
    fold = collector.fold
    attachPtr = collector.attachPtr

    ### Tuple ###
    @attachPtr(tuple, "__iter__")
    @llfunc(descriptive=True)
    def tuple__iter__(self):
        iterator = allocate(tupleiterator)
        store(iterator, "parent", self)
        store(iterator, "iterCurrent", allocate(int))
        return iterator

    # TODO bounds check?
    @attachPtr(xtypes.TupleType, "__getitem__")
    @llfunc
    def tuple__getitem__(self, key):
        return loadArray(self, key)

    ### List ###
    @attachPtr(list, "__getitem__")
    @llfunc(descriptive=True)
    def list__getitem__(self, index):
        return loadArray(self, -1)

    @attachPtr(list, "__setitem__")
    @llfunc(descriptive=True)
    def list__setitem__(self, index, value):
        storeArray(self, -1, value)

    @attachPtr(list, "append")
    @llfunc(descriptive=True)
    def list_append(self, value):
        storeArray(self, -1, value)

    @attachPtr(list, "__iter__")
    @llfunc(descriptive=True)
    def list__iter__(self):
        iterator = allocate(listiterator)
        store(iterator, "parent", self)
        store(iterator, "iterCurrent", allocate(int))
        return iterator

    @attachPtr(xtypes.ListIteratorType, "next")
    @llfunc(descriptive=True)
    def listiterator_next(self):
        store(self, "iterCurrent", load(self, "iterCurrent"))
        return loadArray(load(self, "parent"), -1)

    ### range ###
    @attachPtr(range, "__iter__")
    @llfunc(descriptive=True)
    def range__iter__(self):
        iterator = allocate(rangeiterator)
        store(iterator, "parent", self)
        store(iterator, "iterCurrent", allocate(int))
        return iterator

    @attachPtr(rangeiterator, "next")
    @llfunc(descriptive=True)
    def rangeiterator_next(self):
        store(self, "iterCurrent", load(self, "iterCurrent"))
        return allocate(int)
