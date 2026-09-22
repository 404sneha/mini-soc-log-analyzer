from collections import defaultdict


def detect_ssh_brute_force(events, threshold=5):
    """
    Detect possible SSH brute-force attacks.

    If the same source IP generates at least `threshold`
    failed login attempts, create a security alert.
    """

    failed_attempts = defaultdict(list)

    for event in events:
        if event["event_type"] == "FAILED_LOGIN":
            source_ip = event.get("source_ip")

            if source_ip:
                failed_attempts[source_ip].append(event)

    alerts = []

    for source_ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            alerts.append({
                "alert_type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": source_ip,
                "failed_attempts": len(attempts),
                "description": (
                    f"Possible SSH brute-force attack detected from "
                    f"{source_ip} with {len(attempts)} failed login attempts."
                )
            })

    return alerts


def detect_invalid_users(events, threshold=2):
    """
    Detect repeated attempts to authenticate using
    non-existent usernames from the same source IP.
    """

    invalid_attempts = defaultdict(list)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            source_ip = event.get("source_ip")

            if source_ip:
                invalid_attempts[source_ip].append(event)

    alerts = []

    for source_ip, attempts in invalid_attempts.items():
        if len(attempts) >= threshold:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "failed_attempts": len(attempts),
                "description": (
                    f"Repeated attempts using invalid usernames detected "
                    f"from {source_ip}."
                )
            })

    return alerts


def detect_success_after_failures(events, threshold=3):
    """
    Detect a successful login from an IP that previously
    generated multiple failed login attempts.
    """

    failed_attempts = defaultdict(int)
    alerts = []

    for event in events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        if event["event_type"] == "FAILED_LOGIN":
            failed_attempts[source_ip] += 1

        elif (
            event["event_type"] == "SUCCESSFUL_LOGIN"
            and failed_attempts[source_ip] >= threshold
        ):
            alerts.append({
                "alert_type": "SUCCESS_AFTER_MULTIPLE_FAILURES",
                "severity": "CRITICAL",
                "source_ip": source_ip,
                "failed_attempts": failed_attempts[source_ip],
                "description": (
                    f"Successful login from {source_ip} occurred after "
                    f"{failed_attempts[source_ip]} failed login attempts."
                )
            })

    return alerts