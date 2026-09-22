import unittest

from src.detector import (
    detect_ssh_brute_force,
    detect_invalid_users,
    detect_success_after_failures,
    detect_password_spraying
)


class TestDetectionRules(unittest.TestCase):

    def test_ssh_brute_force_detection(self):
        events = [
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "192.168.1.50"
            }
            for _ in range(5)
        ]

        alerts = detect_ssh_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "SSH_BRUTE_FORCE"
        )
        self.assertEqual(
            alerts[0]["severity"],
            "HIGH"
        )


    def test_invalid_user_detection(self):
        events = [
            {
                "event_type": "INVALID_USER",
                "source_ip": "10.10.10.25"
            },
            {
                "event_type": "INVALID_USER",
                "source_ip": "10.10.10.25"
            }
        ]

        alerts = detect_invalid_users(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "INVALID_USER_ENUMERATION"
        )
        self.assertEqual(
            alerts[0]["severity"],
            "MEDIUM"
        )


    def test_success_after_failures(self):
        events = [
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "192.168.1.50"
            },
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "192.168.1.50"
            },
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "192.168.1.50"
            },
            {
                "event_type": "SUCCESSFUL_LOGIN",
                "source_ip": "192.168.1.50"
            }
        ]

        alerts = detect_success_after_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "SUCCESS_AFTER_MULTIPLE_FAILURES"
        )
        self.assertEqual(
            alerts[0]["severity"],
            "CRITICAL"
        )


    def test_password_spraying_detection(self):
        events = [
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "10.10.10.50",
                "username": "admin"
            },
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "10.10.10.50",
                "username": "guest"
            },
            {
                "event_type": "FAILED_LOGIN",
                "source_ip": "10.10.10.50",
                "username": "developer"
            }
        ]

        alerts = detect_password_spraying(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "PASSWORD_SPRAYING"
        )
        self.assertEqual(
            alerts[0]["severity"],
            "HIGH"
        )
        self.assertEqual(
            alerts[0]["targeted_usernames"],
            3
        )


if __name__ == "__main__":
    unittest.main()