from __future__ import absolute_import

from ..stubcollector import stubgenerator

import hashlib


@stubgenerator
def makeHashlibStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr
    staticFold = collector.staticFold

    ### new ###
    @export
    @attachPtr(hashlib, "new")
    @llfunc
    def hashlib_new(name, data=b'', usedforsecurity=True):
        return allocate(hashlib._hashlib.HASH)

    ### md5 ###
    @export
    @attachPtr(hashlib, "md5")
    @llfunc
    def hashlib_md5(data=b'', usedforsecurity=True):
        return allocate(hashlib._hashlib.HASH)

    ### sha1 ###
    @export
    @attachPtr(hashlib, "sha1")
    @llfunc
    def hashlib_sha1(data=b'', usedforsecurity=True):
        return allocate(hashlib._hashlib.HASH)

    ### sha224 ###
    @export
    @attachPtr(hashlib, "sha224")
    @llfunc
    def hashlib_sha224(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha256 ###
    @export
    @attachPtr(hashlib, "sha256")
    @llfunc
    def hashlib_sha256(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha384 ###
    @export
    @attachPtr(hashlib, "sha384")
    @llfunc
    def hashlib_sha384(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha512 ###
    @export
    @attachPtr(hashlib, "sha512")
    @llfunc
    def hashlib_sha512(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha3_224 ###
    @export
    @attachPtr(hashlib, "sha3_224")
    @llfunc
    def hashlib_sha3_224(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha3_256 ###
    @export
    @attachPtr(hashlib, "sha3_256")
    @llfunc
    def hashlib_sha3_256(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha3_384 ###
    @export
    @attachPtr(hashlib, "sha3_384")
    @llfunc
    def hashlib_sha3_384(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### sha3_512 ###
    @export
    @attachPtr(hashlib, "sha3_512")
    @llfunc
    def hashlib_sha3_512(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### shake_128 ###
    @export
    @attachPtr(hashlib, "shake_128")
    @llfunc
    def hashlib_shake_128(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### shake_256 ###
    @export
    @attachPtr(hashlib, "shake_256")
    @llfunc
    def hashlib_shake_256(data=b''):
        return allocate(hashlib._hashlib.HASH)

    ### blake2b ###
    @export
    @attachPtr(hashlib, "blake2b")
    @llfunc
    def hashlib_blake2b(data=b'', digest_size=64, key=b'', salt=b'', person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, inner_size=0, last_node=False, usedforsecurity=True):
        return allocate(hashlib._hashlib.HASH)

    ### blake2s ###
    @export
    @attachPtr(hashlib, "blake2s")
    @llfunc
    def hashlib_blake2s(data=b'', digest_size=32, key=b'', salt=b'', person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, inner_size=0, last_node=False, usedforsecurity=True):
        return allocate(hashlib._hashlib.HASH)

    ### HASH methods ###
    hash_type = type(hashlib.md5())

    @attachPtr(hash_type, "update")
    @llfunc
    def hash_update(self, data):
        return allocate(type(None))

    @attachPtr(hash_type, "digest")
    @llfunc
    def hash_digest(self):
        return allocate(bytes)

    @attachPtr(hash_type, "hexdigest")
    @llfunc
    def hash_hexdigest(self):
        return allocate(str)

    @attachPtr(hash_type, "copy")
    @llfunc
    def hash_copy(self):
        return allocate(hash_type)

    @attachPtr(hash_type, "block_size")
    @llfunc
    def hash_block_size_get(self):
        return allocate(int)

    @attachPtr(hash_type, "digest_size")
    @llfunc
    def hash_digest_size_get(self):
        return allocate(int)

    @attachPtr(hash_type, "name")
    @llfunc
    def hash_name_get(self):
        return allocate(str)

    ### shake digest methods ###
    @attachPtr(hash_type, "hexdigest")
    @llfunc
    def shake_hexdigest(self, length):
        return allocate(str)

    @attachPtr(hash_type, "digest")
    @llfunc
    def shake_digest(self, length):
        return allocate(bytes)

    ### file_digest ###
    @export
    @attachPtr(hashlib, "file_digest")
    @llfunc
    def hashlib_file_digest(file, digest, /, *_args):
        return allocate(hashlib._hashlib.HASH)

    ### algorithms_available ###
    @llfunc
    def hashlib_algorithms_available_get():
        return allocate(set)

    ### algorithms_guaranteed ###
    @llfunc
    def hashlib_algorithms_guaranteed_get():
        return allocate(set)

    ### pbkdf2_hmac ###
    @export
    @attachPtr(hashlib, "pbkdf2_hmac")
    @llfunc
    def hashlib_pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
        return allocate(bytes)

    ### scrypt ###
    @export
    @attachPtr(hashlib, "scrypt")
    @llfunc
    def hashlib_scrypt(password, salt, n, r, p, maxmem=0, dklen=64):
        return allocate(bytes)
