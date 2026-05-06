"""
Framework Mock Objects for Entry Point Analysis.

When analyzing web framework entry points (Flask, Django, FastAPI), 
request parameters like `request.args`, `request.GET`, `request.POST` need to be 
modeled as structured objects that return tainted values.

This module provides mock object constructors that create properly-structured
symbolic values with attributes and methods that propagate taint correctly.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Set
import z3

from ..z3model.values import SymbolicValue, ValueTag
from ..z3model.taint_lattice import SourceType, TaintLabel, SymbolicTaintLabel


@dataclass
class MockAttribute:
    """A mock attribute on a framework object."""
    name: str
    value: SymbolicValue
    taint_label: Optional[TaintLabel] = None
    symbolic_taint: Optional[SymbolicTaintLabel] = None


@dataclass
class MockMethod:
    """A mock method on a framework object."""
    name: str
    return_value: SymbolicValue
    taint_label: Optional[TaintLabel] = None
    symbolic_taint: Optional[SymbolicTaintLabel] = None


@dataclass
class MockFrameworkObject:
    """
    A mock framework object with attributes and methods.
    
    Used for:
    - Flask: request.args, request.form, request.json
    - Django: request.GET, request.POST, request.META
    - FastAPI: request.query_params, request.form_data
    """
    base_value: SymbolicValue  # The underlying symbolic value for the object
    attributes: Dict[str, MockAttribute] = field(default_factory=dict)
    methods: Dict[str, MockMethod] = field(default_factory=dict)


def create_flask_request_mock(base_obj_id: int) -> MockFrameworkObject:
    """
    Create a mock Flask request object.
    
    Provides:
    - request.args (ImmutableMultiDict) - GET parameters
    - request.form (ImmutableMultiDict) - POST form data
    - request.json (dict) - JSON body
    - request.cookies (dict) - Cookies
    - request.headers (dict) - HTTP headers
    - request.files (dict) - Uploaded files
    """
    # Base request object
    base_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_{base_obj_id}"))
    
    # Create args object (dict-like with .get() method)
    args_obj_id = base_obj_id + 1
    args_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_args_{args_obj_id}"))
    
    # args.get() returns tainted string
    args_get_return = SymbolicValue(ValueTag.STR, z3.Int(f"request_args_get_{args_obj_id}"))
    args_get_taint = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location="request.args.get()"
    )
    args_get_symbolic = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    args_method = MockMethod(
        name="get",
        return_value=args_get_return,
        taint_label=args_get_taint,
        symbolic_taint=args_get_symbolic
    )
    
    # Create args attribute with the .get() method
    args_mock = MockFrameworkObject(
        base_value=args_value,
        methods={"get": args_method}
    )
    
    # Similar for form
    form_obj_id = base_obj_id + 2
    form_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_form_{form_obj_id}"))
    form_get_return = SymbolicValue(ValueTag.STR, z3.Int(f"request_form_get_{form_obj_id}"))
    form_get_taint = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location="request.form.get()"
    )
    form_get_symbolic = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    form_method = MockMethod(
        name="get",
        return_value=form_get_return,
        taint_label=form_get_taint,
        symbolic_taint=form_get_symbolic
    )
    
    form_mock = MockFrameworkObject(
        base_value=form_value,
        methods={"get": form_method}
    )
    
    # Similar for json
    json_obj_id = base_obj_id + 3
    json_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_json_{json_obj_id}"))
    json_taint = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location="request.json"
    )
    json_symbolic = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    # Create the request object with all attributes
    request_mock = MockFrameworkObject(
        base_value=base_value,
        attributes={
            "args": MockAttribute(
                name="args",
                value=args_value,
                taint_label=None,  # The object itself isn't tainted, but its methods return tainted values
                symbolic_taint=None
            ),
            "form": MockAttribute(
                name="form",
                value=form_value,
                taint_label=None,
                symbolic_taint=None
            ),
            "json": MockAttribute(
                name="json",
                value=json_value,
                taint_label=json_taint,
                symbolic_taint=json_symbolic
            ),
        }
    )
    
    # Store the nested mocks so they can be looked up later
    # (This is a simplified approach; in production we'd use a registry)
    request_mock._nested_mocks = {
        args_value: args_mock,
        form_value: form_mock,
    }
    
    return request_mock


def create_django_request_mock(base_obj_id: int) -> MockFrameworkObject:
    """
    Create a mock Django request object.
    
    Provides:
    - request.GET (QueryDict) - GET parameters
    - request.POST (QueryDict) - POST form data
    - request.META (dict) - HTTP headers and meta info
    - request.COOKIES (dict) - Cookies
    """
    base_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_{base_obj_id}"))
    
    # Create GET object (QueryDict with .get() method)
    get_obj_id = base_obj_id + 1
    get_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_GET_{get_obj_id}"))
    
    get_method_return = SymbolicValue(ValueTag.STR, z3.Int(f"request_GET_get_{get_obj_id}"))
    get_method_taint = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location="request.GET.get()"
    )
    get_method_symbolic = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    get_method = MockMethod(
        name="get",
        return_value=get_method_return,
        taint_label=get_method_taint,
        symbolic_taint=get_method_symbolic
    )
    
    get_mock = MockFrameworkObject(
        base_value=get_value,
        methods={"get": get_method}
    )
    
    # Similar for POST
    post_obj_id = base_obj_id + 2
    post_value = SymbolicValue(ValueTag.OBJ, z3.Int(f"request_POST_{post_obj_id}"))
    
    post_method_return = SymbolicValue(ValueTag.STR, z3.Int(f"request_POST_get_{post_obj_id}"))
    post_method_taint = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location="request.POST.get()"
    )
    post_method_symbolic = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    post_method = MockMethod(
        name="get",
        return_value=post_method_return,
        taint_label=post_method_taint,
        symbolic_taint=post_method_symbolic
    )
    
    post_mock = MockFrameworkObject(
        base_value=post_value,
        methods={"get": post_method}
    )
    
    request_mock = MockFrameworkObject(
        base_value=base_value,
        attributes={
            "GET": MockAttribute(
                name="GET",
                value=get_value,
                taint_label=None,
                symbolic_taint=None
            ),
            "POST": MockAttribute(
                name="POST",
                value=post_value,
                taint_label=None,
                symbolic_taint=None
            ),
        }
    )
    
    # Store nested mocks
    request_mock._nested_mocks = {
        get_value: get_mock,
        post_value: post_mock,
    }
    
    return request_mock


def get_framework_mock(param_name: str, entry_type: str, base_obj_id: int) -> Optional[MockFrameworkObject]:
    """
    Get a framework mock object for a given parameter.
    
    Args:
        param_name: Parameter name (e.g., "request")
        entry_type: Entry point type (e.g., "flask_route", "django_view")
        base_obj_id: Base object ID for allocation
    
    Returns:
        MockFrameworkObject if this is a recognized framework parameter, else None
    """
    if param_name == "request":
        if entry_type in ("flask_route", "fastapi_route"):
            return create_flask_request_mock(base_obj_id)
        elif entry_type == "django_view":
            return create_django_request_mock(base_obj_id)
    
    return None
