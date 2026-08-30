"""Operator-facing command-line interface for SecureTrap.

Lets an operator inspect SecureTrap's persisted alert state from the
terminal, without running ad-hoc Python. This is a thin
presentation/entry-point layer only: all aggregation and querying is
delegated to AlertReporter (which itself delegates to AlertStore) —
the CLI performs no SQL, no aggregation, no detection, and no writes
of its own.

Usage:
    python -m core.cli.main summary [--db PATH]
    python -m core.cli.main alerts [--limit N] [--db PATH]
"""

import argparse
import sys
from typing import Optional, Sequence

from core.alert_engine.alert_store import AlertStore
from core.alert_engine.report import AlertReporter

DEFAULT_DB_PATH = "data/securetrap_live_alerts.db"
DEFAULT_ALERTS_LIMIT = 10


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI's argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m core.cli.main",
        description="Inspect SecureTrap's persisted alert state (read-only).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary_parser = subparsers.add_parser("summary", help="Show aggregate alert counts.")
    summary_parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to the SQLite alert database (default: {DEFAULT_DB_PATH}).",
    )

    alerts_parser = subparsers.add_parser("alerts", help="Show recent alerts.")
    alerts_parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to the SQLite alert database (default: {DEFAULT_DB_PATH}).",
    )
    alerts_parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_ALERTS_LIMIT,
        help=f"Maximum number of alerts to show (default: {DEFAULT_ALERTS_LIMIT}).",
    )

    return parser


def _print_summary(reporter: AlertReporter) -> None:
    """Print AlertReporter.summary() in a human-readable form."""
    summary = reporter.summary()
    print(f"Total alerts: {summary.total_alerts}")
    print(f"Anomaly alerts: {summary.anomaly_alerts}")
    print(f"Normal alerts: {summary.normal_alerts}")
    print(f"Latest timestamp: {summary.latest_timestamp}")


def _print_alerts(reporter: AlertReporter, limit: int) -> int:
    """Print AlertReporter.recent(limit) in a human-readable form.

    Returns:
        0 on success, or a non-zero exit code if `limit` is invalid.
    """
    try:
        alerts = reporter.recent(limit=limit)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not alerts:
        print("No alerts found.")
        return 0

    for alert in alerts:
        print(
            f"timestamp={alert.timestamp} "
            f"source_ip={alert.source_ip} "
            f"session_id={alert.session_id} "
            f"event_type={alert.event_type} "
            f"command={alert.command!r} "
            f"prediction={alert.prediction} "
            f"score={alert.score} "
            f"is_anomaly={alert.is_anomaly}"
        )

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments, excluding the program name. If
            None, argparse reads from sys.argv[1:].

    Returns:
        Process exit code: 0 on success, non-zero on error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    alert_store = AlertStore(args.db)
    reporter = AlertReporter(alert_store)

    if args.command == "summary":
        _print_summary(reporter)
        return 0

    if args.command == "alerts":
        return _print_alerts(reporter, args.limit)

    # Unreachable while subparsers are required=True; kept as a safe
    # fallback rather than assuming argparse's behavior never changes.
    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())