"""Focused tests for refactored typeinfo core generic/union representation and module exports."""

from __future__ import annotations

import collections
import collections.abc
import contextvars
import re
from typing import Annotated, ClassVar, Final, Generic, Literal, TypeVar

from pyflow.analysis.typeinfo.core import descriptors, signatures, types, typesystem, visitors
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    UNSUPPORTED,
    AnyType,
    ClassDescriptor,
    Instance,
    LiteralType,
    NeverType,
    NoneType,
    TypeSystem,
    TypeVarType,
    UnionType,
    Variance,
    make_union,
    normalize_generic_args,
)
from pyflow.analysis.typeinfo.query.service import TypeInfoService


class Animal:
    pass


class Dog(Animal):
    pass


class Cat(Animal):
    pass


T_co = TypeVar("T_co", covariant=True)
T_contra = TypeVar("T_contra", contravariant=True)
T_inv = TypeVar("T_inv")


class Producer(Generic[T_co]):
    pass


class Consumer(Generic[T_contra]):
    pass


class Box(Generic[T_inv]):
    pass


def test_variance_aware_generic_subtyping_on_builtins_and_user_generics():
    ts = TypeSystem()
    animal = ts.convert_type_hint(Animal)
    dog = ts.convert_type_hint(Dog)
    cat = ts.convert_type_hint(Cat)
    assert isinstance(animal, Instance)
    assert isinstance(dog, Instance)
    assert isinstance(cat, Instance)

    # list is invariant
    list_animal = ts.convert_type_hint(list[Animal])
    list_dog = ts.convert_type_hint(list[Dog])
    assert ts.is_subtype(list_dog, list_dog)
    assert not ts.is_subtype(list_dog, list_animal)
    assert not ts.is_subtype(list_animal, list_dog)

    # frozenset is covariant
    fset_animal = ts.convert_type_hint(frozenset[Animal])
    fset_dog = ts.convert_type_hint(frozenset[Dog])
    assert ts.is_subtype(fset_dog, fset_animal)
    assert not ts.is_subtype(fset_animal, fset_dog)

    # collections.abc.Mapping is invariant in key and covariant in value
    mapping_inst = ts.convert_type_hint(collections.abc.Mapping)
    assert isinstance(mapping_inst, Instance)
    mapping_desc = mapping_inst.type
    assert mapping_desc.parameter_variance(0) is Variance.INVARIANT
    assert mapping_desc.parameter_variance(1) is Variance.COVARIANT
    str_t = ts.convert_type_hint(str)
    map_str_dog = Instance(mapping_desc, (str_t, dog))
    map_str_animal = Instance(mapping_desc, (str_t, animal))
    map_dog_str = Instance(mapping_desc, (dog, str_t))
    map_animal_str = Instance(mapping_desc, (animal, str_t))
    assert ts.is_subtype(map_str_dog, map_str_animal)
    assert not ts.is_subtype(map_str_animal, map_str_dog)
    assert not ts.is_subtype(map_dog_str, map_animal_str)

    # User-defined covariant / contravariant / invariant generics via TypeVarType
    prod_desc = ClassDescriptor(Producer)
    prod_desc.type_parameters = (TypeVarType("T_co", variance=Variance.COVARIANT),)
    cons_desc = ClassDescriptor(Consumer)
    cons_desc.type_parameters = (TypeVarType("T_contra", variance=Variance.CONTRAVARIANT),)
    box_desc = ClassDescriptor(Box)
    box_desc.type_parameters = (TypeVarType("T_inv", variance=Variance.INVARIANT),)

    assert ts.is_subtype(Instance(prod_desc, (dog,)), Instance(prod_desc, (animal,)))
    assert not ts.is_subtype(Instance(prod_desc, (animal,)), Instance(prod_desc, (dog,)))

    assert ts.is_subtype(Instance(cons_desc, (animal,)), Instance(cons_desc, (dog,)))
    assert not ts.is_subtype(Instance(cons_desc, (dog,)), Instance(cons_desc, (animal,)))
    assert ts.subtype_distance(Instance(cons_desc, (dog,)), Instance(cons_desc, (animal,))) == 1

    assert not ts.is_subtype(Instance(box_desc, (dog,)), Instance(box_desc, (animal,)))
    assert not ts.is_subtype(Instance(box_desc, (animal,)), Instance(box_desc, (dog,)))
    assert not ts.is_subtype(Instance(prod_desc, (cat,)), Instance(prod_desc, (dog,)))

    # Unparameterized generic remains compatible with parameterized instances (gradual Any args)
    raw_list = ts.convert_type_hint(list)
    assert ts.is_subtype(list_dog, raw_list)
    assert ts.is_subtype(raw_list, list_dog)


def test_union_canonicalization_and_literal_equality():
    ts = TypeSystem()
    int_t = ts.convert_type_hint(int)
    str_t = ts.convert_type_hint(str)
    bool_t = ts.convert_type_hint(bool)
    assert isinstance(int_t, Instance)
    assert isinstance(str_t, Instance)
    assert isinstance(bool_t, Instance)

    # NeverType arms are dropped when inhabited arms exist
    u = UnionType((NeverType(), int_t, NeverType()))
    assert u.items == (int_t,)

    # make_union flattens, deduplicates, unwraps singletons, and returns Never on empty
    assert make_union(()) == NeverType()
    assert make_union((NeverType(), NeverType())) == NeverType()
    assert make_union((NeverType(), int_t)) == int_t
    nested = make_union((int_t, UnionType((int_t, str_t)), NeverType()))
    assert nested == UnionType((int_t, str_t))

    # collapse_any=False preserves Any by default; collapse_any=True collapses to Any
    with_any = make_union((ANY, int_t))
    assert isinstance(with_any, UnionType)
    assert ANY in with_any.items
    assert make_union((ANY, int_t), collapse_any=True) == ANY

    # LiteralType equality compares both value and base class (1 vs True)
    lit_one = LiteralType(1, int_t)
    lit_true = LiteralType(True, bool_t)
    assert lit_one != lit_true
    assert lit_one == LiteralType(1, int_t)


def test_class_descriptor_refresh_and_normalize_generic_args():
    expected_arities = [
        (collections.defaultdict, 2),
        (collections.deque, 1),
        (collections.Counter, 1),
        (re.Pattern, 1),
        (re.Match, 1),
        (contextvars.ContextVar, 1),
        (dict, 2),
        (list, 1),
    ]
    for cls, expected in expected_arities:
        desc = ClassDescriptor(cls)
        assert desc.generic_arity == expected
        desc.refresh(cls)
        assert desc.generic_arity == expected, f"refresh() lost generic arity for {cls}"

    ts = TypeSystem()
    int_t = ts.convert_type_hint(int)
    str_t = ts.convert_type_hint(str)
    dict_desc = ClassDescriptor(dict)
    box_desc = ClassDescriptor(Box)
    box_desc.type_parameters = (TypeVarType("T_inv", variance=Variance.INVARIANT),)

    # User generics without hardcoded builtin arity stay bare unless pad_unparameterized=True
    assert normalize_generic_args(box_desc, ()) == ()
    assert normalize_generic_args(box_desc, (), pad_unparameterized=True) == (ANY,)

    # Builtins with known hardcoded arity normalize missing/excess args
    assert normalize_generic_args(dict_desc, ()) == (ANY, ANY)
    assert normalize_generic_args(dict_desc, (str_t,)) == (str_t, ANY)
    assert normalize_generic_args(dict_desc, (str_t, int_t, str_t)) == (str_t, int_t)


def test_convert_type_hint_modern_wrappers_and_literals():
    ts = TypeSystem()
    int_t = ts.convert_type_hint(int)
    str_t = ts.convert_type_hint(str)
    assert isinstance(int_t, Instance)
    assert isinstance(str_t, Instance)

    assert ts.convert_type_hint(Annotated[int, "meta"]) == int_t
    assert ts.convert_type_hint(Final[str]) == str_t
    assert ts.convert_type_hint(ClassVar[list[int]]) == ts.convert_type_hint(list[int])

    lit_single = ts.convert_type_hint(Literal[42])
    assert lit_single == LiteralType(42, int_t)

    lit_multi = ts.convert_type_hint(Literal["a", "b"])
    assert isinstance(lit_multi, UnionType)
    assert set(lit_multi.items) == {LiteralType("a", str_t), LiteralType("b", str_t)}

    # Preserve existing TypeVar contract
    tv = TypeVar("TV")
    assert ts.convert_type_hint(tv) == AnyType()
    assert ts.convert_type_hint(tv, unsupported=UNSUPPORTED) == UNSUPPORTED


def test_refactored_module_reexports_and_service_compatibility():
    # Core re-exports point to identical objects across submodules
    assert typesystem.UnionType is types.UnionType
    assert typesystem.make_union is types.make_union
    assert typesystem.normalize_generic_args is types.normalize_generic_args
    assert typesystem.ClassDescriptor is descriptors.ClassDescriptor
    assert typesystem.TypeVisitor is visitors.TypeVisitor
    assert typesystem.InferredSignature is signatures.InferredSignature

    # TypeInfoService retains its public and internal compatibility surface
    svc = TypeInfoService()
    for attr in (
        "collect_module",
        "fact_of",
        "signature_of",
        "members_of",
        "inference_result",
        "_resolve_annotation",
        "_collected_modules",
        "_module_imports",
    ):
        assert hasattr(svc, attr), f"TypeInfoService missing expected attribute {attr}"
