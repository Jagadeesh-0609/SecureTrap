"""Dependency providers for the SecureTrap API.

Every dependency here is resolved per-request via FastAPI's Depends()
— never constructed at import time. This is what keeps importing or
creating the API free of filesystem/database side effects: nothing in
this module runs until a request actually asks for it.
"""

from fastapi import Depends

from core.alert_engine.alert_store import AlertStore
from core.app.config import AppConfig, load_config


def get_app_config() -> AppConfig:
    """Resolve SecureTrap's AppConfig (CLI > environment > default).

    Pure value resolution — see core.app.config.load_config(). No
    filesystem or database access happens here; only environment
    variables are read.
    """
    return load_config()


def get_alert_store(config: AppConfig = Depends(get_app_config)) -> AlertStore:
    """Provide an AlertStore bound to the configured database path.

    Constructed fresh per request rather than held as a module-level
    singleton, so there is no global mutable state here and tests can
    cleanly override this dependency (e.g.
    `app.dependency_overrides[get_alert_store] = lambda: isolated_store`)
    to point at a temporary database. AlertStore's own constructor is
    idempotent (CREATE TABLE IF NOT EXISTS), so constructing it fresh
    per request has no harmful effect — it does not duplicate or
    reinterpret any of AlertStore's own persistence logic.
    """
    return AlertStore(config.database_path)