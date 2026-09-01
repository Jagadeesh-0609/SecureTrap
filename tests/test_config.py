"""Isolated unit tests for core.app.config (AppConfig / load_config()).

Configuration construction performs no I/O, so no tmp_path or real
filesystem/database access is needed anywhere in this file. Real
os.environ is never touched — every test passes its own `env` dict.
"""

from pathlib import Path

import pytest

from core.app.config import (
    DEFAULT_DATABASE_PATH,
    DEFAULT_DATASET_PATH,
    DEFAULT_LOG_PATH,
    DEFAULT_POLL_INTERVAL,
    ENV_DATASET,
    ENV_DB,
    ENV_LOG,
    ENV_POLL_INTERVAL,
    AppConfig,
    load_config,
)


def test_default_configuration_values():
    config = load_config(env={})

    assert config.dataset_path == Path(DEFAULT_DATASET_PATH)
    assert config.log_path == Path(DEFAULT_LOG_PATH)
    assert config.database_path == Path(DEFAULT_DATABASE_PATH)
    assert config.poll_interval == DEFAULT_POLL_INTERVAL


def test_environment_override_for_dataset():
    config = load_config(env={ENV_DATASET: "/custom/dataset.csv"})
    assert config.dataset_path == Path("/custom/dataset.csv")


def test_environment_override_for_log():
    config = load_config(env={ENV_LOG: "/custom/cowrie.json"})
    assert config.log_path == Path("/custom/cowrie.json")


def test_environment_override_for_database():
    config = load_config(env={ENV_DB: "/custom/alerts.db"})
    assert config.database_path == Path("/custom/alerts.db")


def test_environment_override_for_poll_interval():
    config = load_config(env={ENV_POLL_INTERVAL: "2.5"})
    assert config.poll_interval == 2.5


def test_cli_over_environment_precedence():
    config = load_config(
        dataset_path="/explicit/dataset.csv",
        log_path="/explicit/cowrie.json",
        database_path="/explicit/alerts.db",
        poll_interval=3.0,
        env={
            ENV_DATASET: "/from-env/dataset.csv",
            ENV_LOG: "/from-env/cowrie.json",
            ENV_DB: "/from-env/alerts.db",
            ENV_POLL_INTERVAL: "9.0",
        },
    )

    assert config.dataset_path == Path("/explicit/dataset.csv")
    assert config.log_path == Path("/explicit/cowrie.json")
    assert config.database_path == Path("/explicit/alerts.db")
    assert config.poll_interval == 3.0


def test_invalid_poll_interval_raises_value_error():
    with pytest.raises(ValueError):
        load_config(poll_interval=-3.0, env={})


def test_zero_poll_interval_rejected():
    with pytest.raises(ValueError):
        load_config(poll_interval=0, env={})


def test_negative_poll_interval_rejected():
    with pytest.raises(ValueError):
        load_config(poll_interval=-0.1, env={})


def test_path_values_are_represented_correctly():
    config = load_config(
        dataset_path="relative/dataset.csv",
        log_path="/absolute/cowrie.json",
        database_path="data/alerts.db",
        env={},
    )

    assert isinstance(config.dataset_path, Path)
    assert isinstance(config.log_path, Path)
    assert isinstance(config.database_path, Path)
    # Paths are used exactly as given — not resolved/made absolute.
    assert config.dataset_path == Path("relative/dataset.csv")
    assert not config.dataset_path.is_absolute()
    assert config.log_path == Path("/absolute/cowrie.json")


def test_no_filesystem_or_database_access_happens_when_config_is_created(monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("Unexpected I/O during config construction")

    monkeypatch.setattr("builtins.open", _fail)

    import sqlite3

    monkeypatch.setattr(sqlite3, "connect", _fail)

    config = load_config(env={})

    assert config.poll_interval == DEFAULT_POLL_INTERVAL


def test_repeated_construction_with_same_environment_is_deterministic():
    fixed_env = {
        ENV_DATASET: "/fixed/dataset.csv",
        ENV_LOG: "/fixed/cowrie.json",
        ENV_DB: "/fixed/alerts.db",
        ENV_POLL_INTERVAL: "1.25",
    }

    first = load_config(env=fixed_env)
    second = load_config(env=fixed_env)

    assert first == second


def test_app_config_post_init_rejects_invalid_poll_interval_directly():
    with pytest.raises(ValueError):
        AppConfig(
            dataset_path=Path(DEFAULT_DATASET_PATH),
            log_path=Path(DEFAULT_LOG_PATH),
            database_path=Path(DEFAULT_DATABASE_PATH),
            poll_interval=0,
        )