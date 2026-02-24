from __future__ import absolute_import

from ..stubcollector import stubgenerator

import copy


@stubgenerator
def makeCopyStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### copy.copy - shallow copy ###
    @export
    @attachPtr(copy.copy)
    @llfunc
    def copy_copy(x):
        return allocate(type(x))

    ### copy.deepcopy - deep copy ###
    @export
    @attachPtr(copy.deepcopy)
    @llfunc
    def copy_deepcopy(x, memo=None):
        return allocate(type(x))

    ### copy.register - custom copy function registration ###
    @export
    @attachPtr(copy.register)
    @llfunc
    def copy_register(cls, function):
        return allocate(type(None))

    ### copy.unregister - unregister custom copy function ###
    @export
    @attachPtr(copy.unregister)
    @llfunc
    def copy_unregister(cls):
        return allocate(type(None))

    ### copy.dispatch_table - table of custom copy functions ###
    @llfunc
    def copy_dispatch_table_get():
        return allocate(dict)

    ### Additional __copy__ and __deepcopy__ method stubs ###
    @llfunc
    def object__copy__(self):
        return allocate(type(self))

    @llfunc
    def object__deepcopy__(self, memo):
        return allocate(type(self))
