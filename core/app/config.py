"""Application configuration for SecureTrap.

Centralizes the application's default paths and runtime constants so
core/app/main.py doesn't scatter them across argument definitions.

This module is configuration only. Constructing an AppConfig performs
no filesystem access, no SQLite access, and no component construction
— it only resolves each value from (in precedence order) an explicit
argument, an environment variable, then a hard-coded default, and
validates poll_interval.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Union

DEFAULT_DATASET_PATH = "data/securetrap_events.csv"
DEFAULT_LOG_PATH = "/home/jagadeesh/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_DATABASE_PATH = "data/securetrap_live_alerts.db"
DEFAULT_POLL_INTERVAL = 0.5

ENV_DATASET = "SECURETRAP_DATASET"
ENV_LOG = "SECURETRAP_LOG"
ENV_DB = "SECURETRAP_DB"
ENV_POLL_INTERVAL = "SECURETRAP_POLL_INTERVAL"


@dataclass
class AppConfig:
    """Resolved SecureTrap application configuration.

    Attributes:
        dataset_path: Path to the baseline DatasetRecord CSV.
        log_path: Path to the Cowrie JSON log to follow.
        database_path: Path to the SQLite alert database.
        poll_interval: Seconds between log polls. Always > 0 — this is
            enforced here so an AppConfig can never exist in an
            invalid state, regardless of how its values were sourced.
    """

    dataset_path: Path
    log_path: Path
    database_path: Path
    poll_interval: float

    def __post_init__(self) -> None:
        if self.poll_interval <= 0:
            raise ValueError(f"poll_interval must be > 0, got {self.poll_interval!r}.")


def load_config(
    *,
    dataset_path: Optional[Union[str, Path]] = None,
    log_path: Optional[Union[str, Path]] = None,
    database_path: Optional[Union[str, Path]] = None,
    poll_interval: Optional[float] = None,
    env: Optional[Mapping[str, str]] = None,
) -> AppConfig:
    """Resolve an AppConfig from explicit values, environment, then defaults.

    Precedence for each field, independently: explicit argument >
    environment variable > hard-coded default. Paths are wrapped in
    `Path(...)` as given — never resolved, made absolute, or otherwise
    normalized into a different location.

    Args:
        dataset_path: Explicit override (e.g. a CLI --dataset value).
            If None, falls back to SECURETRAP_DATASET, then
            DEFAULT_DATASET_PATH.
        log_path: Explicit override for the Cowrie log path. If None,
            falls back to SECURETRAP_LOG, then DEFAULT_LOG_PATH.
        database_path: Explicit override for the SQLite database path.
            If None, falls back to SECURETRAP_DB, then
            DEFAULT_DATABASE_PATH.
        poll_interval: Explicit override for the poll interval. If
            None, falls back to SECURETRAP_POLL_INTERVAL, then
            DEFAULT_POLL_INTERVAL.
        env: Mapping to read environment variables from. Defaults to
            os.environ. Exposed as a parameter purely for testing.

    Returns:
        A validated AppConfig.

    Raises:
        ValueError: If the resolved poll_interval is not a valid
            positive number.
    """
    environment: Mapping[str, str] = env if env is not None else os.environ

    resolved_dataset = (
        dataset_path if dataset_path is not None else environment.get(ENV_DATASET, DEFAULT_DATASET_PATH)
    )
    resolved_log = log_path if log_path is not None else environment.get(ENV_LOG, DEFAULT_LOG_PATH)
    resolved_database = (
        database_path if database_path is not None else environment.get(ENV_DB, DEFAULT_DATABASE_PATH)
    )

    if poll_interval is not None:
        resolved_poll_interval = float(poll_interval)
    elif ENV_POLL_INTERVAL in environment:
        resolved_poll_interval = float(environment[ENV_POLL_INTERVAL])
    else:
        resolved_poll_interval = DEFAULT_POLL_INTERVAL

    return AppConfig(
        dataset_path=Path(resolved_dataset),
        log_path=Path(resolved_log),
        database_path=Path(resolved_database),
        poll_interval=resolved_poll_interval,
    )