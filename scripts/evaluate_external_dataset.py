import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path("data/external/salty_seagull/extracted")
SUMMARY = Path("data/external/salty_seagull/event_type_summary.csv")
REPORT = Path("reports/external_dataset/evaluation_report.txt")


def main():
    event_types = Counter()
    protocols = Counter()
    source_ips = set()
    total = invalid = command_events = missing_timestamps = 0
    files_scanned = 0

    for path in sorted(ROOT.iterdir()):
        if not path.is_file():
            continue

        files_scanned += 1
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        invalid += 1
                        continue
                except json.JSONDecodeError:
                    invalid += 1
                    continue

                total += 1
                event_types[event.get("eventid", "missing")] += 1
                protocols[event.get("protocol", "missing")] += 1

                if event.get("src_ip"):
                    source_ips.add(event["src_ip"])

                if event.get("eventid") == "cowrie.command.input":
                    command_events += 1

                if not event.get("timestamp"):
                    missing_timestamps += 1

    REPORT.parent.mkdir(parents=True, exist_ok=True)

    with REPORT.open("w", encoding="utf-8") as f:
        f.write("SecureTrap External Dataset Evaluation\n")
        f.write("=" * 38 + "\n\n")
        f.write(f"Dataset: {ROOT}\n")
        f.write(f"Files scanned: {files_scanned}\n")
        f.write(f"Valid records: {total}\n")
        f.write(f"Invalid records: {invalid}\n")
        f.write(f"Unique source IPs: {len(source_ips)}\n")
        f.write(f"Command-input events: {command_events}\n")
        f.write(f"Records missing timestamps: {missing_timestamps}\n\n")

        f.write("Event types:\n")
        for name, count in event_types.most_common():
            f.write(f"  {name}: {count}\n")

        f.write("\nProtocols:\n")
        for name, count in protocols.most_common():
            f.write(f"  {name}: {count}\n")

        f.write("\nEvaluation limitations:\n")
        f.write("- No verified ground-truth attack labels are provided here.\n")
        f.write("- Accuracy, precision, recall, and F1 are not calculated.\n")
        f.write("- No command-input events were found in this dataset.\n")
        f.write("- Command-based detection cannot be validated with these records.\n")
        f.write("- This report profiles data; it does not run the AI model.\n")

    print(f"Files scanned: {files_scanned}")
    print(f"Valid records: {total}")
    print(f"Invalid records: {invalid}")
    print(f"Unique source IPs: {len(source_ips)}")
    print(f"Command-input events: {command_events}")
    print(f"Event types: {len(event_types)}")
    print(f"Report saved: {REPORT}")


if __name__ == "__main__":
    main()
