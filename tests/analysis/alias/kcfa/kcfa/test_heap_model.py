"""Tests for heap model: Field and FieldKind."""

import pytest
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import (
    Field,
    FieldKind,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import attr, elem, value, unknown


class TestFieldKind:
    """Tests for FieldKind enum."""
    
    def test_all_kinds_exist(self):
        """Test that all expected field kinds are defined."""
        assert FieldKind.ATTRIBUTE
        assert FieldKind.ELEMENT
        assert FieldKind.VALUE
        assert FieldKind.UNKNOWN
    
    def test_kind_values(self):
        """Test field kind enum values."""
        assert FieldKind.ATTRIBUTE.value == "attr"
        assert FieldKind.ELEMENT.value == "elem"
        assert FieldKind.VALUE.value == "value"
        assert FieldKind.UNKNOWN.value == "unknown"


class TestField:
    """Tests for Field dataclass."""
    
    def test_attribute_field_creation(self):
        """Test creating an attribute field."""
        field = Field(FieldKind.ATTRIBUTE, "foo")
        assert field.kind == FieldKind.ATTRIBUTE
        assert field.name == "foo"
    
    def test_element_field_creation(self):
        """Test creating an element field."""
        field = Field(FieldKind.ELEMENT)
        assert field.kind == FieldKind.ELEMENT
        assert field.name is None
    
    def test_value_field_creation(self):
        """Test creating a value field."""
        field = Field(FieldKind.VALUE)
        assert field.kind == FieldKind.VALUE
        assert field.name is None
    
    def test_unknown_field_creation(self):
        """Test creating an unknown field."""
        field = Field(FieldKind.UNKNOWN)
        assert field.kind == FieldKind.UNKNOWN
        assert field.name is None
    
    def test_attribute_without_name_raises(self):
        """Test that ATTRIBUTE field without name raises ValueError."""
        with pytest.raises(ValueError, match="ATTRIBUTE field must have name"):
            Field(FieldKind.ATTRIBUTE, None)
    
    def test_element_with_name_raises(self):
        """Test that ELEMENT field with name raises ValueError."""
        with pytest.raises(ValueError, match="elem field should not have name"):
            Field(FieldKind.ELEMENT, "should_not_be_here")
    
    def test_value_with_name_raises(self):
        """Test that VALUE field with name raises ValueError."""
        with pytest.raises(ValueError, match="value field should not have name"):
            Field(FieldKind.VALUE, "should_not_be_here")
    
    def test_unknown_with_name_raises(self):
        """Test that UNKNOWN field with name raises ValueError."""
        with pytest.raises(ValueError, match="unknown field should not have name"):
            Field(FieldKind.UNKNOWN, "should_not_be_here")
    
    def test_string_representation_attribute(self):
        """Test __str__ for attribute field."""
        field = Field(FieldKind.ATTRIBUTE, "my_attr")
        assert str(field) == ".my_attr"
    
    def test_string_representation_element(self):
        """Test __str__ for element field."""
        field = Field(FieldKind.ELEMENT)
        assert str(field) == ".elem"
    
    def test_string_representation_value(self):
        """Test __str__ for value field."""
        field = Field(FieldKind.VALUE)
        assert str(field) == ".value"
    
    def test_string_representation_unknown(self):
        """Test __str__ for unknown field."""
        field = Field(FieldKind.UNKNOWN)
        assert str(field) == ".unknown"
    
    def test_equality_same_attribute(self):
        """Test equality for same attribute fields."""
        field1 = Field(FieldKind.ATTRIBUTE, "foo")
        field2 = Field(FieldKind.ATTRIBUTE, "foo")
        assert field1 == field2
    
    def test_equality_different_attribute(self):
        """Test inequality for different attribute fields."""
        field1 = Field(FieldKind.ATTRIBUTE, "foo")
        field2 = Field(FieldKind.ATTRIBUTE, "bar")
        assert field1 != field2
    
    def test_equality_element_fields(self):
        """Test equality for element fields (all equal)."""
        field1 = Field(FieldKind.ELEMENT)
        field2 = Field(FieldKind.ELEMENT)
        assert field1 == field2
    
    def test_equality_different_kinds(self):
        """Test inequality for different field kinds."""
        field1 = Field(FieldKind.ELEMENT)
        field2 = Field(FieldKind.VALUE)
        assert field1 != field2
    
    def test_hashable(self):
        """Test that Field can be used in sets/dicts."""
        field1 = Field(FieldKind.ATTRIBUTE, "foo")
        field2 = Field(FieldKind.ATTRIBUTE, "foo")  # Same as field1
        field3 = Field(FieldKind.ATTRIBUTE, "bar")
        field4 = Field(FieldKind.ELEMENT)
        
        fields = {field1, field2, field3, field4}
        assert len(fields) == 3  # field1 and field2 are equal
    
    def test_frozen(self):
        """Test that Field is immutable."""
        field = Field(FieldKind.ATTRIBUTE, "foo")
        with pytest.raises(AttributeError):
            field.name = "bar"


class TestFieldConstructors:
    """Tests for field convenience constructors."""
    
    def test_attr_constructor(self):
        """Test attr() convenience constructor."""
        field = attr("my_attribute")
        assert field.kind == FieldKind.ATTRIBUTE
        assert field.name == "my_attribute"
        assert str(field) == ".my_attribute"
    
    def test_elem_constructor(self):
        """Test elem() convenience constructor."""
        field = elem()
        assert field.kind == FieldKind.ELEMENT
        assert field.name is None
        assert str(field) == ".elem"
    
    def test_value_constructor(self):
        """Test value() convenience constructor."""
        field = value()
        assert field.kind == FieldKind.VALUE
        assert field.name is None
        assert str(field) == ".value"
    
    def test_unknown_constructor(self):
        """Test unknown() convenience constructor."""
        field = unknown()
        assert field.kind == FieldKind.UNKNOWN
        assert field.name is None
        assert str(field) == ".unknown"
    
    def test_multiple_attributes(self):
        """Test creating multiple different attributes."""
        field1 = attr("name")
        field2 = attr("age")
        field3 = attr("address")
        
        assert field1 != field2
        assert field2 != field3
        assert field1.kind == field2.kind == field3.kind == FieldKind.ATTRIBUTE


class TestFieldUsagePatterns:
    """Test realistic field usage patterns."""
    
    def test_object_attributes(self):
        """Test modeling object attribute access."""
        name_field = attr("name")
        age_field = attr("age")
        email_field = attr("email")
        
        # All are distinct fields
        assert name_field != age_field
        assert age_field != email_field
    
    def test_list_elements(self):
        """Test modeling list element access."""
        elem_field = elem()
        
        # All list indices map to same abstract field
        # This models list[0], list[1], etc. as list.elem
        assert elem_field == elem()
    
    def test_dict_values(self):
        """Test modeling dictionary value access."""
        val_field = value()
        
        # All dict keys map to same abstract field (key-insensitive)
        # This models dict["key1"], dict["key2"], etc. as dict.value
        assert val_field == value()
    
    def test_dynamic_attribute_access(self):
        """Test modeling dynamic attribute access (getattr/setattr)."""
        unknown_field = unknown()
        
        # Dynamic access where attribute name is not statically known
        assert unknown_field.kind == FieldKind.UNKNOWN
    
    def test_field_in_heap_key(self, object_factory):
        """Test using Field as part of heap location key."""
        obj = object_factory()
        
        # Heap locations are keyed by (object, field) tuples
        loc1 = (obj, attr("name"))
        loc2 = (obj, attr("age"))
        loc3 = (obj, elem())
        
        heap = {loc1: "points-to-1", loc2: "points-to-2", loc3: "points-to-3"}
        
        assert len(heap) == 3
        assert heap[loc1] == "points-to-1"
    
    def test_method_attribute_vs_data_attribute(self):
        """Test that method and data attributes are different fields."""
        data_attr = attr("value")
        method_attr = attr("compute")
        
        # Same abstraction - both are attributes
        assert data_attr.kind == method_attr.kind
        # But different names
        assert data_attr != method_attr
    
    def test_dunder_attributes(self):
        """Test modeling special attributes."""
        dict_field = attr("__dict__")
        class_field = attr("__class__")
        init_field = attr("__init__")
        
        assert dict_field != class_field
        assert dict_field.kind == FieldKind.ATTRIBUTE
    
    def test_container_element_abstraction(self):
        """Test that container elements are abstracted to single field."""
        # All container types that use element abstraction
        list_elem = elem()
        set_elem = elem()
        tuple_elem = elem()
        
        # All are the same abstract element field
        assert list_elem == set_elem == tuple_elem


class TestFieldInConstraints:
    """Test Field usage in constraint scenarios."""
    
    def test_load_constraint_field(self, variable_factory):
        """Test field in load constraint: target = base.field."""
        from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import LoadConstraint
        
        base = variable_factory("obj")
        target = variable_factory("result")
        field = attr("name")
        
        constraint = LoadConstraint(base, field, target)
        assert constraint.field == field
    
    def test_store_constraint_field(self, variable_factory):
        """Test field in store constraint: base.field = source."""
        from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import StoreConstraint
        
        base = variable_factory("obj")
        source = variable_factory("value")
        field = attr("name")
        
        constraint = StoreConstraint(base, field, source)
        assert constraint.field == field
    
    def test_different_fields_in_constraints(self, variable_factory):
        """Test that different fields create different constraints."""
        from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import LoadConstraint
        
        base = variable_factory("obj")
        target = variable_factory("result")
        
        load_name = LoadConstraint(base, attr("name"), target)
        load_age = LoadConstraint(base, attr("age"), target)
        
        assert load_name != load_age

