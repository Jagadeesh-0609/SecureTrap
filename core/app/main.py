"""SecureTrap Application Entry Point.

Assembles the existing modular components into one continuously
running live-monitoring process:

    baseline CSV -> DatasetRecord -> ModelManager.fit() [once]
        -> LiveJsonLogReader -> IngestionPipeline
        -> SecureTrapService (LiveDetectionPipeline, AlertDispatcher, AlertStore)

This module is an assembly layer only. It implements no parsing,
validation, feature extraction, model logic, dispatch logic, or
persistence logic of its own — every one of those already belongs to
an existing component this module wires together. It also performs no
anomaly filtering itself: AlertDispatcher alone decides which results
become alerts, and this module never inspects `is_anomaly`.

Run with:
    python -m core.app.main [--dataset PATH] [--log PATH] [--db PATH]
                             [--poll-interval FLOAT]

This is separate from the existing read-only reporting CLI
(`python -m core.cli.main summary|alerts`): this module *runs* live
monitoring; that one only *reads* what has already been persisted.
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Union

from core.ai_engine.model_manager import ModelManager
from core.alert_engine.alert import Alert, AlertBuilder
from core.alert_engine.alert_store import AlertStore
from core.dataset_manager.builder import DatasetBuilder, DatasetRecord
from core.honeypot_engine.cowrie_adapter import CowrieAdapter
from core.honeypot_engine.ingestion import IngestionPipeline
from core.honeypot_engine.live_reader import LiveJsonLogReader
from core.log_processor.enricher import EventEnricher
from core.log_processor.processor import LogProcessor
from core.runtime.alert_dispatch import AlertDispatcher
from core.runtime.live_detection import LiveDetectionPipeline
from core.runtime.service import SecureTrapService

DEFAULT_DATASET_PATH = "data/securetrap_events.csv"
DEFAULT_LOG_PATH = "/home/jagadeesh/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_DB_PATH = "data/securetrap_live_alerts.db"
DEFAULT_POLL_INTERVAL = 0.5


def _parse_bool(value: str) -> bool:
    """Parse a CSV boolean field as written by DatasetWriter ("True"/"False")."""
    return value.strip().lower() == "true"


def _load_dataset_records(path: Union[str, Path]) -> List[DatasetRecord]:
    """Load baseline DatasetRecord objects from a DatasetRecord-schema CSV.

    Standard-library csv module only (no pandas). Never modifies the
    file — opened strictly for reading.

    Args:
        path: Path to a CSV matching DatasetRecord's exact column
            schema, as produced by DatasetWriter.

    Returns:
        One DatasetRecord per data row, in file order. Empty if the
        file has a header but no data rows.

    Raises:
        FileNotFoundError: If `path` does not exist.
    """
    records: List[DatasetRecord] = []

    with open(path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            records.append(
                DatasetRecord(
                    timestamp=row["timestamp"],
                    source_ip=row["source_ip"],
                    session_id=row["session_id"],
                    protocol=row["protocol"],
                    honeypot=row["honeypot"],
                    event_type=row["event_type"],
                    category=row["category"],
                    severity=row["severity"],
                    command=row["command"],
                    has_command=_parse_bool(row["has_command"]),
                    command_length=int(row["command_length"]),
                    has_url=_parse_bool(row["has_url"]),
                    has_ip_address=_parse_bool(row["has_ip_address"]),
                    has_file_path=_parse_bool(row["has_file_path"]),
                    has_shell_metacharacters=_parse_bool(row["has_shell_metacharacters"]),
                )
            )

    return records


def _positive_float(value: str) -> float:
    """argparse type= validator: parse a strictly positive float."""
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid number.") from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"--poll-interval must be > 0, got {value!r}.")

    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build the application's argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m core.app.main",
        description="Run SecureTrap live anomaly monitoring.",
    )
    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET_PATH,
        help=f"Baseline DatasetRecord CSV path (default: {DEFAULT_DATASET_PATH}).",
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_PATH,
        help=f"Cowrie JSON log path to follow (default: {DEFAULT_LOG_PATH}).",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"SQLite alert database path (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--poll-interval",
        type=_positive_float,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Seconds between log polls (default: {DEFAULT_POLL_INTERVAL}).",
    )
    return parser


class _PrintingAlertStore:
    """Wraps an AlertStore, printing an alert only after it is actually persisted.

    Exposes the same `save(alert) -> int` interface SecureTrapService
    already relies on, so SecureTrapService itself needs no changes.
    All persistence behavior (schema, SQL, directory creation) is
    delegated entirely to the wrapped AlertStore; this class adds only
    an operator-facing print after a successful save.

    It never inspects `is_anomaly` or filters anything — by the time
    SecureTrapService calls save(), AlertDispatcher has already
    ensured only anomalous results reached this point.
    """

    def __init__(self, alert_store: AlertStore) -> None:
        self._alert_store = alert_store

    def save(self, alert: Alert) -> int:
        alert_id = self._alert_store.save(alert)
        print(
            "ALERT | "
            f"timestamp={alert.timestamp} | "
            f"source_ip={alert.source_ip} | "
            f"session={alert.session_id} | "
            f"event={alert.event_type} | "
            f"command={alert.command!r} | "
            f"prediction={alert.prediction} | "
            f"score={alert.score}"
        )
        return alert_id


def assemble_service(
    args: argparse.Namespace,
    *,
    model_manager: Optional[ModelManager] = None,
    reader_factory: Callable[..., object] = LiveJsonLogReader,
    ingestion_pipeline_factory: Callable[..., object] = IngestionPipeline,
    live_detection_pipeline_factory: Callable[..., object] = LiveDetectionPipeline,
    alert_dispatcher_factory: Callable[..., object] = AlertDispatcher,
    alert_store_factory: Callable[..., object] = AlertStore,
    load_dataset_records: Callable[[Union[str, Path]], List[DatasetRecord]] = _load_dataset_records,
):
    """Load the baseline, fit a model once, and wire up a SecureTrapService.

    This is the entire assembly layer: every component it constructs
    already exists elsewhere and is used exactly as designed. No
    parsing, feature extraction, detection, dispatch, or persistence
    logic is implemented here — and no anomaly filtering either;
    AlertDispatcher alone decides what becomes an alert.

    Args:
        args: Parsed CLI arguments (see build_parser()): `.dataset`,
            `.log`, `.db`, `.poll_interval`.
        model_manager: Override for the ModelManager instance.
            Defaults to a fresh ModelManager(), fit once on the
            baseline below.
        reader_factory: Override for constructing the log reader.
            Defaults to LiveJsonLogReader.
        ingestion_pipeline_factory: Override for constructing the
            ingestion pipeline. Defaults to IngestionPipeline.
        live_detection_pipeline_factory: Override for constructing the
            detection pipeline. Defaults to LiveDetectionPipeline.
        alert_dispatcher_factory: Override for constructing the alert
            dispatcher. Defaults to AlertDispatcher.
        alert_store_factory: Override for constructing the alert
            store. Defaults to AlertStore.
        load_dataset_records: Override for loading baseline records.
            Defaults to _load_dataset_records.

    Returns:
        A tuple (service, ingestion_pipeline, baseline_records), so
        the caller can run `service.run(ingestion_pipeline.process())`
        and report on the baseline that was used.

    Raises:
        FileNotFoundError: If the baseline dataset does not exist.
        ValueError: If the baseline dataset contains zero records.
    """
    baseline_records = load_dataset_records(args.dataset)

    if not baseline_records:
        raise ValueError(f"Baseline dataset at {args.dataset!r} contains zero records.")

    manager = model_manager if model_manager is not None else ModelManager()
    manager.fit(baseline_records)

    reader = reader_factory(args.log, poll_interval=args.poll_interval)
    ingestion_pipeline = ingestion_pipeline_factory(reader.follow(), CowrieAdapter())

    detection_pipeline = live_detection_pipeline_factory(
        log_processor=LogProcessor(),
        event_enricher=EventEnricher(),
        dataset_builder=DatasetBuilder(),
        model_manager=manager,
    )
    alert_dispatcher = alert_dispatcher_factory(alert_builder=AlertBuilder())
    alert_store = alert_store_factory(args.db)

    service = SecureTrapService(
        live_detection_pipeline=detection_pipeline,
        alert_dispatcher=alert_dispatcher,
        alert_store=_PrintingAlertStore(alert_store),
    )

    return service, ingestion_pipeline, baseline_records


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Application entry point: assemble and run SecureTrap live monitoring.

    Args:
        argv: Command-line arguments, excluding the program name. If
            None, argparse reads from sys.argv[1:].

    Returns:
        Process exit code: 0 on success or a clean Ctrl+C stop,
        non-zero if the baseline dataset is missing/empty or argument
        parsing fails. Unexpected runtime errors are not caught here
        and propagate to the caller.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        service, ingestion_pipeline, baseline_records = assemble_service(args)
    except FileNotFoundError:
        print(f"Error: baseline dataset not found at {args.dataset!r}.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("SecureTrap live monitoring started.")
    print(f"Baseline records: {len(baseline_records)}")
    print(f"Log file: {args.log}")
    print(f"Alert database: {args.db}")
    print(f"Poll interval: {args.poll_interval}")
    print("Press Ctrl+C to stop.")

    try:
        service.run(ingestion_pipeline.process())
    except KeyboardInterrupt:
        print("SecureTrap monitoring stopped.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())