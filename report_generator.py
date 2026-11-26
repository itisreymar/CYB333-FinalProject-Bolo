"""Generate a summary of security events and detected threats."""

from datetime import datetime


def generate_report(events, alerts, warnings, output_path):
    """Create and save a readable security analysis report."""
    successful = sum(
        event["event_type"] == "SUCCESS" for event in events
    )
    failed = sum(
        event["event_type"] == "FAILED" for event in events
    )

    suspicious_ips = sorted({
        alert["source_ip"] for alert in alerts
    })

    lines = [
        "=" * 55,
        "SECURITY LOG MONITORING AND ALERT SYSTEM",
        "=" * 55,
        f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        "",
        "ANALYSIS SUMMARY",
        f"Total events analyzed: {len(events)}",
        f"Successful logins: {successful}",
        f"Failed logins: {failed}",
        f"Security alerts: {len(alerts)}",
        f"Invalid records skipped: {len(warnings)}",
        "",
        "DETECTED SECURITY ALERTS"
    ]

    if not alerts:
        lines.append("No suspicious activity detected.")

    for alert in alerts:
        lines.extend([
            "-" * 55,
            f"[{alert['severity']}] {alert['type']}",
            f"Timestamp: {alert['timestamp']}",
            f"Source IP: {alert['source_ip']}",
            f"Username: {alert['username']}",
            f"Failed attempts: {alert['failed_attempts']}"
        ])

    lines.extend(["", "SUSPICIOUS IP ADDRESSES"])
    lines.extend(suspicious_ips or ["None detected."])

    if warnings:
        lines.extend(["", "DATA VALIDATION WARNINGS"])
        lines.extend(warnings)

    lines.append("=" * 55)

    report = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report + "\n")

    return report
