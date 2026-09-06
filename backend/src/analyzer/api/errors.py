"""RFC 9457 Problem Details error handling (LLD 9). Step 6.2.

Every error leaving this API is ``application/problem+json`` with ``type``,
``title``, ``status`` and ``detail``. No bare ``{"detail": "..."}``, no HTML
error pages, no stack traces over the wire -- CLAUDE.md's API rules, and the
reason a client can tell a rejected upload from a missing capture without
string-matching prose.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError as FastApiRequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_CONTENT_TYPE: Final = "application/problem+json"

# RFC 9457 extension members cross the same boundary as every other key the
# API emits, so they are camelCase too (CLAUDE.md: conversion happens only
# at the API boundary). These dicts are built by hand rather than by a
# Pydantic alias generator, so the spelling is explicit here.

PROBLEM_BASE_URI: Final = "https://ipsec-analyzer.invalid/problems"
"""``type`` is a URI that identifies the *kind* of problem, not a URL anyone
fetches. RFC 9457 section 3.1.1 is explicit that it need not resolve; using a
reserved ``.invalid`` domain says so out loud rather than implying a docs site
that does not exist yet."""


class ApiError(Exception):
    """A failure that should reach the client as a Problem Details document."""

    def __init__(
        self,
        status_code: int,
        title: str,
        detail: str,
        *,
        problem_type: str = "about:blank",
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.title = title
        self.detail = detail
        self.problem_type = problem_type
        self.extra = extra or {}


class NotFoundError(ApiError):
    def __init__(self, resource: str, resource_id: object) -> None:
        super().__init__(
            status.HTTP_404_NOT_FOUND,
            title="Resource not found",
            detail=f"No {resource} with id {resource_id}",
            problem_type=f"{PROBLEM_BASE_URI}/not-found",
        )


class ValidationError(ApiError):
    def __init__(self, detail: str, *, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            title="Request validation failed",
            detail=detail,
            problem_type=f"{PROBLEM_BASE_URI}/validation",
            extra=extra,
        )


class PayloadTooLargeError(ApiError):
    def __init__(self, limit_bytes: int) -> None:
        super().__init__(
            status.HTTP_413_CONTENT_TOO_LARGE,
            title="Upload exceeds the size limit",
            detail=f"Captures are capped at {limit_bytes} bytes (LLD section 9)",
            problem_type=f"{PROBLEM_BASE_URI}/payload-too-large",
            extra={"limitBytes": limit_bytes},
        )


class DependencyUnavailableError(ApiError):
    """A capability this endpoint needs is not installed on this deployment.

    Distinct from a 500: nothing went wrong with the request, and retrying it
    unchanged will fail the same way until an operator installs something. The
    detail therefore carries the remedy, which is safe to expose because it
    names a package, never anything about this machine.
    """

    def __init__(self, detail: str, *, capability: str) -> None:
        super().__init__(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            title="Service unavailable",
            detail=detail,
            problem_type=f"{PROBLEM_BASE_URI}/dependency-unavailable",
            extra={"capability": capability},
        )


class ConflictError(ApiError):
    def __init__(self, detail: str, *, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            status.HTTP_409_CONFLICT,
            title="Conflicting request",
            detail=detail,
            problem_type=f"{PROBLEM_BASE_URI}/conflict",
            extra=extra,
        )


def problem_response(
    request: Request,
    *,
    status_code: int,
    title: str,
    detail: str,
    problem_type: str = "about:blank",
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": problem_type,
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": str(request.url.path),
    }
    body.update(extra or {})
    return JSONResponse(status_code=status_code, content=body, media_type=PROBLEM_CONTENT_TYPE)


_TITLES: Final[dict[int, str]] = {
    status.HTTP_400_BAD_REQUEST: "Bad request",
    status.HTTP_404_NOT_FOUND: "Resource not found",
    status.HTTP_405_METHOD_NOT_ALLOWED: "Method not allowed",
    status.HTTP_409_CONFLICT: "Conflicting request",
    status.HTTP_413_CONTENT_TOO_LARGE: "Upload exceeds the size limit",
    status.HTTP_422_UNPROCESSABLE_CONTENT: "Request validation failed",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal server error",
    status.HTTP_503_SERVICE_UNAVAILABLE: "Service unavailable",
}


def install_error_handlers(app: FastAPI) -> None:
    """Route every error shape FastAPI can produce through Problem Details."""

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return problem_response(
            request,
            status_code=exc.status_code,
            title=exc.title,
            detail=exc.detail,
            problem_type=exc.problem_type,
            extra=exc.extra,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem_response(
            request,
            status_code=exc.status_code,
            title=_TITLES.get(exc.status_code, "Request failed"),
            detail=str(exc.detail),
        )

    @app.exception_handler(FastApiRequestValidationError)
    async def _validation_error(
        request: Request, exc: FastApiRequestValidationError
    ) -> JSONResponse:
        return problem_response(
            request,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            title=_TITLES[status.HTTP_422_UNPROCESSABLE_CONTENT],
            detail="One or more request parameters are invalid",
            problem_type=f"{PROBLEM_BASE_URI}/validation",
            extra={
                "errors": [
                    {"loc": [str(part) for part in error["loc"]], "msg": error["msg"]}
                    for error in exc.errors()
                ]
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001 - FastAPI requires the parameter; the body is deliberately opaque
        # Deliberately opaque. An unhandled exception's message can carry a
        # connection string or a filesystem path, and NFR-6 keeps analyst data
        # local -- including in error text.
        return problem_response(
            request,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            title=_TITLES[status.HTTP_500_INTERNAL_SERVER_ERROR],
            detail="The request could not be completed. See the server log for details.",
        )
