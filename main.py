
"""Run the automated security log monitoring system."""

import argparse
import sys
from csv import Error as csv_error
from pathlib import Path

from log_parser import parse_logs
from detector import detect_threats
from report_generator import generate_report


def main():
    """Coordinate log parsing, detection, and reporting."""
    parser = argparse.ArgumentParser(
        description="Automated security log analysis tool."
    )

    parser.add_argument(
        "--file",
        default="security_logs.csv",
        help="Path to the input CSV log file."
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failures required to trigger an alert."
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Detection time window in minutes."
    )

    parser.add_argument(
        "--output",
        default="security_report.txt",
        help="Path to the generated security report."
    )

    args = parser.parse_args()

    try:
        # Prevent the report from overwriting the original logs.
        if Path(args.file).resolve() == Path(args.output).resolve():
            raise ValueError(
                "Input and output files must be different."
            )

        # Read and validate security logs.
        events, warnings = parse_logs(args.file)

        # Analyze authentication events.
        alerts = detect_threats(
            events,
            threshold=args.threshold,
            window_minutes=args.window
        )

        # Generate and display the security report.
        report = generate_report(
            events,
            alerts,
            warnings,
            args.output
        )

        print(report)
        print(f"\nReport saved to: {args.output}")

        return 0

    except (OSError, ValueError, csv_error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
