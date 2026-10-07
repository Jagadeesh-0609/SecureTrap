"""SecureTrap API application factory.

Builds a thin FastAPI layer around the existing SecureTrap services
(AlertStore, via dependency injection) — no engine logic lives here.
Creating this app, or simply importing this module, performs no
filesystem, database, or model I/O: every dependency (AlertStore,
AppConfig) is resolved lazily, per request, never at import or
app-construction time. Nothing here imports anything from
core.ai_engine, core.honeypot_engine, or core.log_processor — the API
cannot accidentally touch the model or require Cowrie to be running.
"""

import logging
import os
from typing import List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import alerts, health
from core.app.logging_config import LOGGER_NAME

# Kept separate from core.app.config.AppConfig on purpose: CORS is a
# concern of this API layer alone, not of the live-monitoring runtime
# those settings describe. The same "environment override, safe
# default" pattern is reused here rather than a different one.
DEFAULT_CORS_ORIGINS = ["http://localhost:3000"]
ENV_CORS_ORIGINS = "SECURETRAP_CORS_ORIGINS"


def _resolve_cors_origins() -> List[str]:
    """Resolve allowed CORS origins for the (future) React dashboard.

    Reads a comma-separated SECURETRAP_CORS_ORIGINS environment
    variable. Falls back to a single safe localhost development
    origin when unset — never a wildcard, and no production frontend
    URL is hard-coded anywhere.
    """
    raw = os.environ.get(ENV_CORS_ORIGINS)
    if not raw:
        return list(DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app() -> FastAPI:
    """Build and return the SecureTrap FastAPI application.

    Safe to call (and to import this module) without Cowrie running,
    without a database file existing yet, and without ever touching
    the AI engine.
    """
    app = FastAPI(title="SecureTrap API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Centralized handler for anything a route doesn't catch itself.

        Does not run for FastAPI's own HTTPException/validation-error
        handling (those remain FastAPI's normal 404/422 responses) —
        only for genuinely unexpected failures. Logs the full
        exception via SecureTrap's existing logger (reused here by
        name, not reconfigured) before returning a generic 500, so
        failures are never silently hidden but internals never leak
        to the client either. Never logs request bodies, headers, or
        any alert field — only the method and path.
        """
        logging.getLogger(LOGGER_NAME).exception(
            "Unhandled API error on %s %s", request.method, request.url.path
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    app.include_router(health.router)
    app.include_router(alerts.router)

    return app


app = create_app()