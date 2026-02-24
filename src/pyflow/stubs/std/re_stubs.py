from __future__ import absolute_import

from ..stubcollector import stubgenerator

import re


@stubgenerator
def makeREStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    @export
    @attachPtr(re, "search")
    @llfunc
    def re_search(pattern, string, flags=0):
        match_obj = allocate(type(re.search("test", "test")))
        if match_obj is not None:
            return match_obj
        return allocate(type(None))

    @export
    @attachPtr(re, "match")
    @llfunc
    def re_match(pattern, string, flags=0):
        match_obj = allocate(type(re.match("test", "test string")))
        if match_obj is not None:
            return match_obj
        return allocate(type(None))

    @export
    @attachPtr(re, "findall")
    @llfunc
    def re_findall(pattern, string, flags=0):
        return allocate(list)

    @export
    @attachPtr(re, "finditer")
    @llfunc
    def re_finditer(pattern, string, flags=0):
        return allocate(type(iter([])))

    @export
    @attachPtr(re, "compile")
    @llfunc
    def re_compile(pattern, flags=0):
        pattern_obj = allocate(type(re.compile("test")))
        return pattern_obj

    @export
    @attachPtr(re, "sub")
    @llfunc
    def re_sub(pattern, repl, string, count=0, flags=0):
        return allocate(str)

    @export
    @attachPtr(re, "split")
    @llfunc
    def re_split(pattern, string, maxsplit=0, flags=0):
        return allocate(list)

    @export
    @attachPtr(re, "escape")
    @llfunc
    def re_escape(pattern):
        return allocate(str)

    @export
    @attachPtr(re, "purge")
    @llfunc
    def re_purge():
        return allocate(type(None))

    ### Match object methods ###
    match_type = type(re.match("test", "test"))

    @attachPtr(match_type, "group")
    @llfunc
    def match_group(self, *args):
        return allocate(str)

    @attachPtr(match_type, "groups")
    @llfunc
    def match_groups(self, default=None):
        return allocate(tuple)

    @attachPtr(match_type, "groupdict")
    @llfunc
    def match_groupdict(self, default=None):
        return allocate(dict)

    @attachPtr(match_type, "start")
    @llfunc
    def match_start(self, group=0):
        return allocate(int)

    @attachPtr(match_type, "end")
    @llfunc
    def match_end(self, group=0):
        return allocate(int)

    @attachPtr(match_type, "span")
    @llfunc
    def match_span(self, group=0):
        return allocate(tuple)

    @attachPtr(match_type, "expand")
    @llfunc
    def match_expand(self, template):
        return allocate(str)

    @attachPtr(match_type, "__getitem__")
    @llfunc
    def match__getitem__(self, group):
        return allocate(str)

    @attachPtr(match_type, "__repr__")
    @llfunc
    def match__repr__(self):
        return allocate(str)

    ### Pattern object methods ###
    pattern_type = type(re.compile("test"))

    @attachPtr(pattern_type, "search")
    @llfunc
    def pattern_search(self, string, pos=0, endpos=None):
        match_obj = allocate(match_type)
        if match_obj is not None:
            return match_obj
        return allocate(type(None))

    @attachPtr(pattern_type, "match")
    @llfunc
    def pattern_match(self, string, pos=0, endpos=None):
        match_obj = allocate(match_type)
        if match_obj is not None:
            return match_obj
        return allocate(type(None))

    @attachPtr(pattern_type, "fullmatch")
    @llfunc
    def pattern_fullmatch(self, string, pos=0, endpos=None):
        match_obj = allocate(match_type)
        if match_obj is not None:
            return match_obj
        return allocate(type(None))

    @attachPtr(pattern_type, "findall")
    @llfunc
    def pattern_findall(self, string, pos=0, endpos=None):
        return allocate(list)

    @attachPtr(pattern_type, "finditer")
    @llfunc
    def pattern_finditer(self, string, pos=0, endpos=None):
        return allocate(type(iter([])))

    @attachPtr(pattern_type, "sub")
    @llfunc
    def pattern_sub(self, repl, string, count=0):
        return allocate(str)

    @attachPtr(pattern_type, "subn")
    @llfunc
    def pattern_subn(self, repl, string, count=0):
        return allocate(tuple)

    @attachPtr(pattern_type, "split")
    @llfunc
    def pattern_split(self, string, maxsplit=0):
        return allocate(list)

    @attachPtr(pattern_type, "__repr__")
    @llfunc
    def pattern__repr__(self):
        return allocate(str)
