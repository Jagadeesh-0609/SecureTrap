import json
from collections import Counter
from pathlib import Path

DATASET = Path("data/external/salty_seagull/cowrie_sample.json")


def main():
    event_types = Counter()
    protocols = Counter()
    source_ips = set()
    valid = 0
    invalid = 0
    command_events = 0
    missing_timestamps = 0

    with DATASET.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    invalid += 1
                    continue
            except json.JSONDecodeError:
                invalid += 1
                continue

            valid += 1
            event_types[event.get("eventid", "missing")] += 1
            protocols[event.get("protocol", "missing")] += 1

            if event.get("src_ip"):
                source_ips.add(event["src_ip"])

            if "cowrie.command.input" == event.get("eventid"):
                command_events += 1

            if not event.get("timestamp"):
                missing_timestamps += 1

    print(f"Dataset: {DATASET}")
    print(f"Valid records: {valid}")
    print(f"Invalid records: {invalid}")
    print(f"Unique source IPs: {len(source_ips)}")
    print(f"Command-input events: {command_events}")
    print(f"Records missing timestamps: {missing_timestamps}")
    print("\nEvent types:")
    for event_type, count in event_types.most_common():
        print(f"  {event_type}: {count}")
    print("\nProtocols:")
    for protocol, count in protocols.most_common():
        print(f"  {protocol}: {count}")


if __name__ == "__main__":
    main()
