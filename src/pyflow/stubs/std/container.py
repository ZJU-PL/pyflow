# @PydevCodeAnalysisIgnore

from __future__ import absolute_import

from ..stubcollector import stubgenerator

from pyflow.util.monkeypatch import xtypes

tupleiterator = xtypes.TupleIteratorType
listiterator = xtypes.ListIteratorType
rangeiterator = xtypes.XRangeIteratorType
dict_key_iterator = xtypes.DictKeyIteratorType
dict_value_iterator = xtypes.DictValueIteratorType
dict_item_iterator = xtypes.DictItemIteratorType
set_iterator = xtypes.SetIteratorType


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
    @attachPtr(tuple, "__getitem__")
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

    ### Dict ###
    @attachPtr(dict, "__getitem__")
    @llfunc(descriptive=True)
    def dict__getitem__(self, key):
        return allocate(object)

    @attachPtr(dict, "__setitem__")
    @llfunc(descriptive=True)
    def dict__setitem__(self, key, value):
        storeDict(self, key, value)

    @attachPtr(dict, "get")
    @llfunc(descriptive=True)
    def dict_get(self, key, default=None):
        if checkDict(self, key):
            return loadDict(self, key)
        return default

    @attachPtr(dict, "__contains__")
    @llfunc(descriptive=True)
    def dict__contains__(self, key):
        return checkDict(self, key)

    @attachPtr(dict, "keys")
    @llfunc(descriptive=True)
    def dict_keys(self):
        iterator = allocate(dict_key_iterator)
        store(iterator, "parent", self)
        return iterator

    @attachPtr(dict, "values")
    @llfunc(descriptive=True)
    def dict_values(self):
        iterator = allocate(dict_value_iterator)
        store(iterator, "parent", self)
        return iterator

    @attachPtr(dict, "items")
    @llfunc(descriptive=True)
    def dict_items(self):
        iterator = allocate(dict_item_iterator)
        store(iterator, "parent", self)
        return iterator

    @attachPtr(dict, "pop")
    @llfunc(descriptive=True)
    def dict_pop(self, key, *default):
        return allocate(object)

    @attachPtr(dict, "popitem")
    @llfunc(descriptive=True)
    def dict_popitem(self):
        return allocate(tuple)

    @attachPtr(dict, "setdefault")
    @llfunc(descriptive=True)
    def dict_setdefault(self, key, default=None):
        if checkDict(self, key):
            return loadDict(self, key)
        storeDict(self, key, default)
        return default

    @attachPtr(dict, "update")
    @llfunc(descriptive=True)
    def dict_update(self, other=None, **kwargs):
        return allocate(type(None))

    @attachPtr(dict, "clear")
    @llfunc(descriptive=True)
    def dict_clear(self):
        return allocate(type(None))

    @attachPtr(dict, "copy")
    @llfunc(descriptive=True)
    def dict_copy(self):
        return allocate(dict)

    @attachPtr(dict, "__iter__")
    @llfunc(descriptive=True)
    def dict__iter__(self):
        return dict_keys(self)

    ### Set ###
    @attachPtr(set, "__contains__")
    @llfunc(descriptive=True)
    def set__contains__(self, item):
        return allocate(bool)

    @attachPtr(set, "add")
    @llfunc(descriptive=True)
    def set_add(self, item):
        return allocate(type(None))

    @attachPtr(set, "remove")
    @llfunc(descriptive=True)
    def set_remove(self, item):
        return allocate(type(None))

    @attachPtr(set, "discard")
    @llfunc(descriptive=True)
    def set_discard(self, item):
        return allocate(type(None))

    @attachPtr(set, "pop")
    @llfunc(descriptive=True)
    def set_pop(self):
        return allocate(object)

    @attachPtr(set, "clear")
    @llfunc(descriptive=True)
    def set_clear(self):
        return allocate(type(None))

    @attachPtr(set, "copy")
    @llfunc(descriptive=True)
    def set_copy(self):
        return allocate(set)

    @attachPtr(set, "union")
    @llfunc(descriptive=True)
    def set_union(self, *others):
        return allocate(set)

    @attachPtr(set, "intersection")
    @llfunc(descriptive=True)
    def set_intersection(self, *others):
        return allocate(set)

    @attachPtr(set, "difference")
    @llfunc(descriptive=True)
    def set_difference(self, *others):
        return allocate(set)

    @attachPtr(set, "symmetric_difference")
    @llfunc(descriptive=True)
    def set_symmetric_difference(self, other):
        return allocate(set)

    @attachPtr(set, "issubset")
    @llfunc(descriptive=True)
    def set_issubset(self, other):
        return allocate(bool)

    @attachPtr(set, "issuperset")
    @llfunc(descriptive=True)
    def set_issuperset(self, other):
        return allocate(bool)

    @attachPtr(set, "__iter__")
    @llfunc(descriptive=True)
    def set__iter__(self):
        iterator = allocate(set_iterator)
        store(iterator, "parent", self)
        return iterator

    ### frozenset ###
    @attachPtr(frozenset, "__contains__")
    @llfunc(descriptive=True)
    def frozenset__contains__(self, item):
        return allocate(bool)

    @attachPtr(frozenset, "union")
    @llfunc(descriptive=True)
    def frozenset_union(self, *others):
        return allocate(frozenset)

    @attachPtr(frozenset, "intersection")
    @llfunc(descriptive=True)
    def frozenset_intersection(self, *others):
        return allocate(frozenset)

    @attachPtr(frozenset, "__iter__")
    @llfunc(descriptive=True)
    def frozenset__iter__(self):
        return allocate(set_iterator)

    ### Additional List methods ###
    @attachPtr(list, "extend")
    @llfunc(descriptive=True)
    def list_extend(self, iterable):
        return allocate(type(None))

    @attachPtr(list, "insert")
    @llfunc(descriptive=True)
    def list_insert(self, index, item):
        return allocate(type(None))

    @attachPtr(list, "remove")
    @llfunc(descriptive=True)
    def list_remove(self, value):
        return allocate(type(None))

    @attachPtr(list, "pop")
    @llfunc(descriptive=True)
    def list_pop(self, index=-1):
        return allocate(object)

    @attachPtr(list, "clear")
    @llfunc(descriptive=True)
    def list_clear(self):
        return allocate(type(None))

    @attachPtr(list, "index")
    @llfunc(descriptive=True)
    def list_index(self, value, start=0, stop=None):
        return allocate(int)

    @attachPtr(list, "count")
    @llfunc(descriptive=True)
    def list_count(self, value):
        return allocate(int)

    @attachPtr(list, "sort")
    @llfunc(descriptive=True)
    def list_sort(self, key=None, reverse=False):
        return allocate(type(None))

    @attachPtr(list, "reverse")
    @llfunc(descriptive=True)
    def list_reverse(self):
        return allocate(type(None))

    @attachPtr(list, "copy")
    @llfunc(descriptive=True)
    def list_copy(self):
        return allocate(list)

    @attachPtr(list, "__contains__")
    @llfunc(descriptive=True)
    def list__contains__(self, item):
        return allocate(bool)

    @attachPtr(list, "__len__")
    @llfunc(descriptive=True)
    def list__len__(self):
        return allocate(int)

    @attachPtr(list, "__add__")
    @llfunc(descriptive=True)
    def list__add__(self, other):
        return allocate(list)

    @attachPtr(list, "__mul__")
    @llfunc(descriptive=True)
    def list__mul__(self, n):
        return allocate(list)

    ### Additional Tuple methods ###
    @attachPtr(tuple, "count")
    @llfunc(descriptive=True)
    def tuple_count(self, value):
        return allocate(int)

    @attachPtr(tuple, "index")
    @llfunc(descriptive=True)
    def tuple_index(self, value, start=0, stop=None):
        return allocate(int)

    @attachPtr(tuple, "__contains__")
    @llfunc(descriptive=True)
    def tuple__contains__(self, item):
        return allocate(bool)

    @attachPtr(tuple, "__len__")
    @llfunc(descriptive=True)
    def tuple__len__(self):
        return allocate(int)

    @attachPtr(tuple, "__add__")
    @llfunc(descriptive=True)
    def tuple__add__(self, other):
        return allocate(tuple)

    @attachPtr(tuple, "__mul__")
    @llfunc(descriptive=True)
    def tuple__mul__(self, n):
        return allocate(tuple)

    ### Dict and Set length ###
    @attachPtr(dict, "__len__")
    @llfunc(descriptive=True)
    def dict__len__(self):
        return allocate(int)

    @attachPtr(set, "__len__")
    @llfunc(descriptive=True)
    def set__len__(self):
        return allocate(int)
