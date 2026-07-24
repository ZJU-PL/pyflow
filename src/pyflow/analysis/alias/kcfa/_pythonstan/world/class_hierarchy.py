"""Maintain lowered-IR class inheritance relationships."""

from typing import Dict, List
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRClass


class ClassHierarchy:
    """Index classes and direct base/subclass relationships by IR identity."""

    bases: Dict[IRClass, List[IRClass]]
    subclasses: Dict[IRClass, List[IRClass]]
    classes: Dict[str, IRClass]

    def __init__(self):
        self.bases = {}
        self.subclasses = {}
        self.classes = {}

    def is_subclass(self, cls: IRClass, sub_cls: IRClass) -> bool:
        """Return whether ``sub_cls`` is recorded as a direct subclass."""
        if cls in self.subclasses and sub_cls in self.subclasses[cls]:
            return True
        else:
            return False

    def add_subclass(self, cls: IRClass, sub_cls: IRClass):
        """Record ``sub_cls`` as directly inheriting from ``cls``."""
        if sub_cls not in self.subclasses[cls]:
            self._add_item(self.bases, sub_cls, cls)
            self._add_item(self.subclasses, cls, sub_cls)

    def get_subclasses(self, cls: IRClass) -> List[IRClass]:
        """Return direct subclasses of ``cls``."""
        return self.subclasses.get(cls, [])

    def get_bases(self, cls: IRClass) -> List[IRClass]:
        """Return direct bases of ``cls``."""
        return self.bases.get(cls, [])

    def add_class(self, class_name: str, ir_class: IRClass):
        """Add a class to the hierarchy"""
        self.classes[class_name] = ir_class
    
    def add_inheritance(self, subclass_name: str, base_class_name: str):
        """Add inheritance relationship between classes"""
        if subclass_name in self.classes and base_class_name in self.classes:
            subclass = self.classes[subclass_name]
            base_class = self.classes[base_class_name]
            self.add_subclass(base_class, subclass)
    
    def add_method(self, class_name: str, method_name: str, method_value):
        """Add a method to a class"""
        # For now, just store the method in the class
        # This is a simplified implementation for testing
        if class_name in self.classes:
            # In a real implementation, this would add to the class's methods
            pass

    @staticmethod
    def _add_item(kv_map, key, value):
        if key in kv_map:
            kv_map[key].append(value)
        else:
            kv_map[key] = [value]
