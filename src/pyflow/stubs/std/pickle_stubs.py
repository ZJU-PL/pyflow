from __future__ import absolute_import

from ..stubcollector import stubgenerator

import pickle


@stubgenerator
def makePickleStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### dump ###
    @export
    @attachPtr(pickle, "dump")
    @llfunc
    def pickle_dump(obj, file, protocol=None, fix_imports=True, buffer_callback=None):
        return allocate(type(None))

    ### dumps ###
    @export
    @attachPtr(pickle, "dumps")
    @llfunc
    def pickle_dumps(obj, protocol=None, fix_imports=True, buffer_callback=None):
        return allocate(bytes)

    ### load ###
    @export
    @attachPtr(pickle, "load")
    @llfunc
    def pickle_load(file, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
        return allocate(object)

    ### loads ###
    @export
    @attachPtr(pickle, "loads")
    @llfunc
    def pickle_loads(data, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
        return allocate(object)

    ### Pickler ###
    @export
    @attachPtr(pickle, "Pickler")
    @llfunc
    def pickle_Pickler(file, protocol=None, fix_imports=True, buffer_callback=None):
        return allocate(pickle.Pickler)

    @attachPtr(pickle.Pickler, "dump")
    @llfunc
    def pickler_dump(self, obj):
        return allocate(type(None))

    @attachPtr(pickle.Pickler, "clear_memo")
    @llfunc
    def pickler_clear_memo(self):
        return allocate(type(None))

    ### Unpickler ###
    @export
    @attachPtr(pickle, "Unpickler")
    @llfunc
    def pickle_Unpickler(file, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
        return allocate(pickle.Unpickler)

    @attachPtr(pickle.Unpickler, "load")
    @llfunc
    def unpickler_load(self):
        return allocate(object)

    ### Constants ###
    @llfunc
    def pickle_HIGHEST_PROTOCOL_get():
        return allocate(int)

    @llfunc
    def pickle_DEFAULT_PROTOCOL_get():
        return allocate(int)

    ### Exceptions ###
    @export
    @attachPtr(pickle, "PickleError")
    @llfunc
    def pickle_PickleError(*args):
        return allocate(pickle.PickleError)

    @export
    @attachPtr(pickle, "PicklingError")
    @llfunc
    def pickle_PicklingError(*args):
        return allocate(pickle.PicklingError)

    @export
    @attachPtr(pickle, "UnpicklingError")
    @llfunc
    def pickle_UnpicklingError(*args):
        return allocate(pickle.UnpicklingError)
