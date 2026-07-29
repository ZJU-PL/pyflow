"""Region analysis for shape analysis.

This module performs region analysis to group objects that may alias.
Regions are computed using union-find: if two objects can be referred
to by the same pointer, they are in the same region.

Note: Regions may have cyclic points-to relationships, so this analysis
is not sound for "region allocation" (objects may escape their regions). (really?)

Also, if a reference is "optionally None" there will be problems.
In general, immutable objects should not be fused.
"""

from pyflow.util.PADS.UnionFind import UnionFind

import collections

from pyflow.analysis.astcollector import getOps

from pyflow.language.python import ast
from pyflow.ir.core import Capabilities


class Region(object):
    """Represents a region (group) of objects.

    A region contains objects that may alias (be referred to by the
    same pointer). Regions are computed using union-find analysis.

    Attributes:
        objects: Frozen set of objects in this region
    """

    def __init__(self, objects):
        """Initialize a region.

        Args:
            objects: Set of objects in this region
        """
        self.objects = frozenset(objects)

    def __contains__(self, obj):
        """Check if object is in this region.

        Args:
            obj: Object to check

        Returns:
            bool: True if object in region
        """
        return obj in self.objects


class RegionAnalysis(object):
    """Performs region analysis to group aliasing objects.

    RegionAnalysis uses union-find to group objects that may alias.
    It processes operations to find objects that are read/written
    together, indicating they may alias.

    Attributes:
        extractor: Program extractor
        entryPoints: List of entry points
        liveCode: Set of live code objects
        uf: UnionFind data structure for region grouping
        liveObjs: Dictionary mapping code to set of live objects
        liveFields: Dictionary mapping code to set of live fields
    """

    def __init__(self, extractor, entryPoints, liveCode, facts):
        """Initialize region analysis.

        Args:
            extractor: Program extractor
            entryPoints: List of entry points
            liveCode: Set of live code objects
        """
        self.extractor = extractor
        self.entryPoints = entryPoints
        self.liveCode = liveCode
        self.facts = facts
        self.uf = UnionFind()

        self.liveObjs = {}
        self.liveFields = {}

    def merge(self, references):
        """Merge references into the same region.

        Uses union-find to group references that may alias.

        Args:
            references: Set of references to merge
        """
        if references:
            self.uf.union(*references)

    def process(self):
        """Process all live code to compute regions.

        Analyzes operations in live code to find objects that are
        read/written together, indicating they may alias. Groups
        these objects into regions.
        """
        # TODO get all fields from heap?

        # Local references
        for code in self.liveCode:
            self.liveObjs[code] = set()
            self.liveFields[code] = set()

            ops, lcls = getOps(code)
            for op in ops:
                reads = self.facts.merged_operation_effect(
                    Capabilities.LIFETIME_OP_READS, code, op
                )
                writes = self.facts.merged_operation_effect(
                    Capabilities.LIFETIME_OP_WRITES, code, op
                )
                allocations = self.facts.merged_operation_effect(
                    Capabilities.LIFETIME_OP_ALLOCATIONS, code, op
                )
                self.liveFields[code].update(reads)
                self.liveFields[code].update(writes)

                if not self.facts.merged_call_targets(code, op):
                    # If the op does not invoke, it does real work.
                    self.merge(reads)
                    self.merge(writes)

                    # TODO seperate by concrete field type before merge

                for cobj in allocations:
                    if not cobj.leaks:
                        self.liveObjs[code].add(cobj)

            for lcl in lcls:
                for ref in self.facts.merged_references(code, lcl):
                    if not ref.leaks:
                        self.liveObjs[code].add(ref)

            # print(code, len(self.liveFields[code]))

    def printGroups(self):

        lut = collections.defaultdict(set)

        for slot in self.uf:
            lut[self.uf[slot]].add(slot)

        print("Groups")
        for key, values in lut.items():
            print(key)
            for slot in values:
                if slot is not key:
                    print("\t", slot)


def evaluate(extractor, entryPoints, liveCode, facts):
    ra = RegionAnalysis(extractor, entryPoints, liveCode, facts)
    ra.process()
    return ra
