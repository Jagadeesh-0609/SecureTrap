"""Offline, baseline-relative evaluation of external SSH command events.

No commands from the dataset are executed. No live alert database is
opened or modified. No ground-truth labels or accuracy metrics are
invented.
"""

import csv
from pathlib import Path

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.feature_matrix import FeatureMatrixBuilder
from core.dataset_manager.builder import DatasetBuilder, DatasetRecord
from core.event_engine.event import AttackEvent
from core.log_processor.enricher import EventEnricher
from core.log_processor.processor import LogProcessor

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "data/securetrap_events.csv"
EXTERNAL = (
    ROOT / "data/external/ssh_command_dataset/ssh_honeypot_dataset.csv"
)
OUTPUT = ROOT / "reports/external_dataset/ssh_command_model_results.csv"

REQUIRED_FIELDS = {
    "timestamp", "source_ip", "session_id", "protocol", "honeypot",
    "event_type", "category", "severity", "command", "has_command",
    "command_length", "has_url", "has_ip_address", "has_file_path",
    "has_shell_metacharacters",
}


def parse_bool(value):
    value = str(value).strip().lower()
    if value not in {"true", "false"}:
        raise ValueError(f"Invalid Boolean value in baseline: {value!r}")
    return value == "true"


def load_baseline(path):
    records = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        missing = REQUIRED_FIELDS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"Baseline CSV is missing required columns: {sorted(missing)}"
            )

        for row in reader:
            records.append(DatasetRecord(
                timestamp=row["timestamp"],
                source_ip=row["source_ip"],
                session_id=row["session_id"],
                protocol=row["protocol"],
                honeypot=row["honeypot"],
                event_type=row["event_type"],
                category=row["category"],
                severity=row["severity"],
                command=row["command"],
                has_command=parse_bool(row["has_command"]),
                command_length=int(row["command_length"]),
                has_url=parse_bool(row["has_url"]),
                has_ip_address=parse_bool(row["has_ip_address"]),
                has_file_path=parse_bool(row["has_file_path"]),
                has_shell_metacharacters=parse_bool(
                    row["has_shell_metacharacters"]
                ),
            ))

    if len(records) < 2:
        raise ValueError(
            f"Need at least 2 baseline records; found {len(records)}"
        )
    return records


def load_external_commands(path):
    records = []
    processor = LogProcessor()
    enricher = EventEnricher()
    builder = DatasetBuilder()

    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        required = {"timestamp", "session_id", "ip", "event_type", "command"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"External CSV is missing required columns: {sorted(missing)}"
            )

        for row in reader:
            command = (row.get("command") or "").strip()
            if row.get("event_type", "").strip() != "exec_command":
                continue
            if not command:
                continue

            event = AttackEvent(
                timestamp=row.get("timestamp", ""),
                source_ip=row.get("ip", ""),
                session_id=row.get("session_id", ""),
                protocol="ssh",
                command=command,
                event_type="ssh.exec_command",
                honeypot="External SSH dataset",
            )
            processed = processor.process(event)
            enriched = enricher.enrich(processed)
            records.append(builder.build(enriched))

    if not records:
        raise ValueError("No non-empty exec_command records found")
    return records


def main():
    for path in (BASELINE, EXTERNAL):
        if not path.is_file():
            raise FileNotFoundError(f"Required input file not found: {path}")

    baseline_records = load_baseline(BASELINE)
    external_records = load_external_commands(EXTERNAL)

    matrix_builder = FeatureMatrixBuilder()
    baseline_matrix = matrix_builder.build(baseline_records)
    external_matrix = matrix_builder.build(external_records)

    # Fit only on the existing baseline. External records are predict-only.
    detector = AnomalyDetector()
    detector.fit(baseline_matrix)
    predictions = detector.predict(external_matrix)
    scores = detector.score(external_matrix)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "timestamp", "session_id", "source_ip", "event_type", "command",
        "command_length", "has_command", "has_url", "has_ip_address",
        "has_file_path", "has_shell_metacharacters",
        "prediction", "is_statistical_anomaly", "decision_score",
    ]

    with OUTPUT.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for record, prediction, score in zip(
            external_records, predictions, scores
        ):
            writer.writerow({
                "timestamp": record.timestamp,
                "session_id": record.session_id,
                "source_ip": record.source_ip,
                "event_type": record.event_type,
                "command": record.command,
                "command_length": record.command_length,
                "has_command": record.has_command,
                "has_url": record.has_url,
                "has_ip_address": record.has_ip_address,
                "has_file_path": record.has_file_path,
                "has_shell_metacharacters": (
                    record.has_shell_metacharacters
                ),
                "prediction": prediction,
                "is_statistical_anomaly": prediction == -1,
                "decision_score": score,
            })

    anomalies = sum(prediction == -1 for prediction in predictions)

    print("Offline external model evaluation completed.")
    print(f"Baseline records used for fitting: {len(baseline_records)}")
    print(f"External command records scored: {len(external_records)}")
    print(f"Statistical anomalies flagged: {anomalies}")
    print(f"Statistical inliers flagged: {len(predictions) - anomalies}")
    print(f"Results: {OUTPUT}")
    print("No external commands were executed.")
    print("No live alert database was accessed or modified.")
    print("These results are not accuracy or attack-confirmation metrics.")


if __name__ == "__main__":
    main()
