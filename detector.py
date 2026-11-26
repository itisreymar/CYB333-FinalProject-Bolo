"""Detect suspicious authentication patterns."""

from collections import defaultdict, deque
from datetime import timedelta


def detect_threats(events, threshold=5, window_minutes=5):
    """Detect repeated failures and suspicious successful logins."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("Detection settings must be positive.")

    failures = defaultdict(deque)
    alerted_ips = set()
    alerts = []
    time_window = timedelta(minutes=window_minutes)

    for event in events:
        ip = event["source_ip"]
        timestamp = event["timestamp"]
        recent_failures = failures[ip]

        # Remove failures outside the configured time window.
        while recent_failures:
            oldest = recent_failures[0]["timestamp"]

            if timestamp - oldest <= time_window:
                break

            recent_failures.popleft()

        if len(recent_failures) < threshold:
            alerted_ips.discard(ip)

        if event["event_type"] == "FAILED":
            recent_failures.append(event)

            # Generate an alert when the threshold is reached.
            if (
                len(recent_failures) >= threshold
                and ip not in alerted_ips
            ):
                alerts.append({
                    "severity": "HIGH",
                    "type": "Possible brute-force activity",
                    "timestamp": timestamp,
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": len(recent_failures)
                })

                alerted_ips.add(ip)

        elif event["event_type"] == "SUCCESS":
            matching_failures = sum(
                failure["username"] == event["username"]
                for failure in recent_failures
            )

            # Detect successful logins after repeated failures.
            if matching_failures >= threshold:
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "Success after repeated failures",
                    "timestamp": timestamp,
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": matching_failures
                })

            # Reset failures for the authenticated user.
            failures[ip] = deque(
                failure for failure in recent_failures
                if failure["username"] != event["username"]
            )

            if len(failures[ip]) < threshold:
                alerted_ips.discard(ip)

    return alerts
