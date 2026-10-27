import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/external/ssh_command_dataset/ssh_honeypot_dataset.csv"
OUTPUT = ROOT / "reports/external_dataset/ssh_command_features.csv"

def extract_features(command):
    command = command or ""
    return {
        "command_length": len(command),
        "has_command": bool(command.strip()),
        "has_url": bool(re.search(r"https?://|ftp://", command, re.I)),
        "has_ip_address": bool(re.search(
            r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", command
        )),
        "has_file_path": bool(re.search(
            r"(?:^|\s)(?:/[\w./-]+|~/[\w./-]+)", command
        )),
        "has_shell_metacharacters": bool(re.search(r"[;&|`$<>]", command)),
    }

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
rows_written = 0

with SOURCE.open(encoding="utf-8-sig", newline="") as source, \
     OUTPUT.open("w", encoding="utf-8", newline="") as destination:
    reader = csv.DictReader(source)
    fields = [
        "timestamp", "session_id", "ip", "event_type", "command",
        "command_length", "has_command", "has_url", "has_ip_address",
        "has_file_path", "has_shell_metacharacters",
    ]
    writer = csv.DictWriter(destination, fieldnames=fields)
    writer.writeheader()

    for row in reader:
        command = (row.get("command") or "").strip()
        if row.get("event_type") != "exec_command" or not command:
            continue

        features = extract_features(command)
        writer.writerow({
            "timestamp": row.get("timestamp", ""),
            "session_id": row.get("session_id", ""),
            "ip": row.get("ip", ""),
            "event_type": row.get("event_type", ""),
            "command": command,
            **features,
        })
        rows_written += 1

print(f"Input: {SOURCE}")
print(f"Output: {OUTPUT}")
print(f"Feature rows written: {rows_written}")
print("No recorded commands were executed.")
