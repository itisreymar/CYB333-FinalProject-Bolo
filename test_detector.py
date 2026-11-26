
"""Automated tests for the security log monitoring system."""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from detector import detect_threats
from log_parser import parse_logs
from report_generator import generate_report


class TestThreatDetector(unittest.TestCase):
    """Test authentication threat detection rules."""

    def setUp(self):
        """Establish a consistent starting timestamp."""
        self.start = datetime(2026, 11, 25, 9, 0, 0)

    def make_event(
        self,
        minutes,
        event_type="FAILED",
        ip="192.0.2.50",
        username="admin"
    ):
        """Create a simulated authentication event."""
        return {
            "timestamp": self.start + timedelta(minutes=minutes),
            "username": username,
            "source_ip": ip,
            "event_type": event_type
        }

    def test_normal_login(self):
        """Normal successful logins should not generate alerts."""
        events = [self.make_event(0, "SUCCESS")]
        self.assertEqual(detect_threats(events), [])

    def test_below_threshold(self):
        """Four failed attempts should not trigger an alert."""
        events = [self.make_event(i) for i in range(4)]
        self.assertEqual(detect_threats(events), [])

    def test_brute_force_detection(self):
        """Five failed attempts should generate a HIGH alert."""
        events = [self.make_event(i) for i in range(5)]
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_success_after_failures(self):
        """Success after repeated failures should be CRITICAL."""
        events = [self.make_event(i) for i in range(5)]
        events.append(self.make_event(5, "SUCCESS"))

        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[1]["severity"], "CRITICAL")

    def test_failures_outside_window(self):
        """Widely spaced failures should not trigger an alert."""
        events = [self.make_event(i * 10) for i in range(5)]
        self.assertEqual(detect_threats(events), [])

    def test_exact_window_boundary(self):
        """Events exactly five minutes apart remain in the window."""
        events = [
            self.make_event(i) for i in [0, 1, 2, 3, 5]
        ]
        self.assertEqual(len(detect_threats(events)), 1)

    def test_different_ip_addresses(self):
        """Failures from different IPs should be tracked separately."""
        events = [
            self.make_event(i, ip=f"192.0.2.{i + 10}")
            for i in range(5)
        ]
        self.assertEqual(detect_threats(events), [])

    def test_duplicate_alert_prevention(self):
        """Continuing failures should not generate duplicate alerts."""
        events = [self.make_event(i) for i in range(6)]
        self.assertEqual(len(detect_threats(events)), 1)

    def test_different_username_success(self):
        """Another user's success should not trigger a CRITICAL alert."""
        events = [self.make_event(i) for i in range(5)]
        events.append(
            self.make_event(5, "SUCCESS", username="guest")
        )

        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_empty_events(self):
        """An empty dataset should return no alerts."""
        self.assertEqual(detect_threats([]), [])

    def test_custom_threshold(self):
        """A custom threshold should change detection sensitivity."""
        events = [self.make_event(i) for i in range(3)]
        alerts = detect_threats(events, threshold=3)

        self.assertEqual(len(alerts), 1)

    def test_invalid_threshold(self):
        """A zero threshold should raise an exception."""
        with self.assertRaises(ValueError):
            detect_threats([], threshold=0)

    def test_invalid_window(self):
        """A negative time window should raise an exception."""
        with self.assertRaises(ValueError):
            detect_threats([], window_minutes=-1)


class TestLogParser(unittest.TestCase):
    """Test CSV parsing and input validation."""

    def test_missing_file(self):
        """A nonexistent file should raise FileNotFoundError."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.csv"

            with self.assertRaises(FileNotFoundError):
                parse_logs(path)

    def test_invalid_columns(self):
        """A CSV missing required columns should be rejected."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.csv"

            path.write_text(
                "username,event_type\nadmin,FAILED\n",
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                parse_logs(path)

    def test_malformed_record(self):
        """Invalid records should be skipped with a warning."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.csv"

            path.write_text(
                "timestamp,username,source_ip,event_type\n"
                "invalid-date,admin,192.0.2.50,FAILED\n"
                "2026-11-25 09:00:00,john,192.0.2.10,SUCCESS\n",
                encoding="utf-8"
            )

            events, warnings = parse_logs(path)

            self.assertEqual(len(events), 1)
            self.assertEqual(len(warnings), 1)


class TestReportGenerator(unittest.TestCase):
    """Test automated security report generation."""

    def test_report_generation(self):
        """A security report should be created successfully."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"

            report = generate_report([], [], [], path)

            self.assertTrue(path.exists())
            self.assertIn("Total events analyzed: 0", report)
            self.assertIn("Security alerts: 0", report)
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                report + "\n"
            )


if __name__ == "__main__":
    unittest.main()
