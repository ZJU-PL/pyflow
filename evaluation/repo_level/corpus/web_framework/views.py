from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from .request import Request
from .response import Response, TemplateResponse


class View(ABC):
    methods: ClassVar[list[str]] = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    def __init__(self, request: Request):
        self.request = request

    def dispatch(self, method: str) -> Response:
        method = method.upper()
        if method not in self.methods:
            return Response(status=405, body="Method Not Allowed")
        handler = getattr(self, method.lower(), None)
        if handler is None:
            return Response(status=405, body="Method Not Allowed")
        return handler()

    @abstractmethod
    def get(self) -> Response:
        pass

    def post(self) -> Response:
        return Response(status=405, body="Method Not Allowed")

    def put(self) -> Response:
        return Response(status=405, body="Method Not Allowed")

    def delete(self) -> Response:
        return Response(status=405, body="Method Not Allowed")

    def patch(self) -> Response:
        return Response(status=405, body="Method Not Allowed")


class TemplateView(View):
    template_name: ClassVar[str] = ""
    context: ClassVar[dict[str, Any]] = {}

    def get_template(self) -> str:
        return self.template_name

    def get_context(self) -> dict[str, Any]:
        return dict(self.context)

    def get(self) -> Response:
        return TemplateResponse(self.get_template(), self.get_context())


class FormView(View):
    form_class: ClassVar[type] | None = None
    success_url: ClassVar[str] = "/"
    template_name: ClassVar[str] = ""

    def get_form(self, data: dict[str, Any] | None = None) -> Any:
        if self.form_class is None:
            raise ValueError("form_class must be defined")
        return self.form_class(data) if data else self.form_class()

    def form_valid(self, form: Any) -> Response:
        from .response import RedirectResponse
        return RedirectResponse(self.success_url)

    def form_invalid(self, form: Any) -> Response:
        return TemplateResponse(self.template_name, {"form": form})

    def get(self) -> Response:
        form = self.get_form()
        return TemplateResponse(self.template_name, {"form": form})

    def post(self) -> Response:
        form = self.get_form(self.request.json if self.request.body else None)
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)


class ListView(View):
    model: ClassVar[type] | None = None
    template_name: ClassVar[str] = ""
    context_object_name: ClassVar[str] = "object_list"

    def get_queryset(self) -> list[Any]:
        if self.model is None:
            return []
        return []

    def get_context(self) -> dict[str, Any]:
        return {self.context_object_name: self.get_queryset()}

    def get(self) -> Response:
        return TemplateResponse(self.template_name, self.get_context())


class DetailView(View):
    model: ClassVar[type] | None = None
    template_name: ClassVar[str] = ""
    context_object_name: ClassVar[str] = "object"
    pk_url_kwarg: ClassVar[str] = "pk"

    def get_object(self) -> Any:
        return None

    def get_context(self) -> dict[str, Any]:
        return {self.context_object_name: self.get_object()}

    def get(self) -> Response:
        return TemplateResponse(self.template_name, self.get_context())
