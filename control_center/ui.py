"""Read-only server-rendered Control Center surface."""

from __future__ import annotations

import inspect

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .router import _db_path, _principal, _scope
from .repository import open_sqlite_repository


router = APIRouter(prefix="/control-center/ui", tags=["Control Center UI"])
templates = Jinja2Templates(directory="templates")
_template_response_params = tuple(inspect.signature(templates.TemplateResponse).parameters)


def _template_response(request: Request, context: dict[str, object]) -> HTMLResponse:
    """Render with both pre- and post-Starlette request-first signatures."""

    if _template_response_params and _template_response_params[0] == "request":
        return templates.TemplateResponse(request, "control_center.html", context)
    return templates.TemplateResponse("control_center.html", {"request": request, **context})


def _read_models(repository, principal) -> dict[str, list[dict[str, object]]]:
    scope = _scope(principal)
    return {
        "customers": repository.customers(customer_scope=scope),
        "inventory": repository.inventory(customer_scope=scope),
        "subscriptions": repository.subscriptions(customer_scope=scope),
    }


@router.get("", response_class=HTMLResponse)
def control_center_ui(request: Request, section: str = "overview") -> HTMLResponse:
    principal = _principal(request, "GET", "/control-center/ui")
    section = section if section in {"overview", "customers", "inventory", "subscriptions"} else "overview"
    with open_sqlite_repository(_db_path()) as repository:
        data = _read_models(repository, principal)

    return _template_response(
        request,
        {
            "section": section,
            "operator": principal.subject,
            "customers": data["customers"],
            "inventory": data["inventory"],
            "subscriptions": data["subscriptions"],
            "license_features": [],
        },
    )
