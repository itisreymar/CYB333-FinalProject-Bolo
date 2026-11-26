"""Read and validate authentication events from a CSV file."""

import csv
import ipaddress
from datetime import datetime


def parse_logs(file_path):
    """Return valid security events and validation warnings."""
    events = []
    warnings = []

    required_fields = {
        "timestamp", "username", "source_ip", "event_type"
    }

    with open(file_path, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        if not required_fields.issubset(reader.fieldnames or []):
            raise ValueError("CSV file is missing required columns.")

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.strptime(
                    row["timestamp"].strip(),
                    "%Y-%m-%d %H:%M:%S"
                )

                username = row["username"].strip()
                source_ip = str(
                    ipaddress.ip_address(row["source_ip"].strip())
                )
                event_type = row["event_type"].strip().upper()

                if not username:
                    raise ValueError("Username is empty.")

                if event_type not in {"SUCCESS", "FAILED"}:
                    raise ValueError("Invalid event type.")

                events.append({
                    "timestamp": timestamp,
                    "username": username,
                    "source_ip": source_ip,
                    "event_type": event_type
                })

            except (ValueError, AttributeError, TypeError) as error:
                warnings.append(
                    f"Skipped line {line_number}: {error}"
                )

    # Process events in chronological order.
    events.sort(key=lambda event: event["timestamp"])

    return events, warnings
