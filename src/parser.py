import re
from datetime import datetime


def parse_log_line(line):
    """
    Parse a Linux authentication log line and extract useful fields.
    """

    pattern = (
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    match = re.match(pattern, line.strip())

    if not match:
        return None

    data = match.groupdict()

    # Extract IP address if one exists in the message
    ip_match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        data["message"]
    )

    data["source_ip"] = ip_match.group(0) if ip_match else None

    # Identify authentication result
    message_lower = data["message"].lower()

    if "failed password" in message_lower:
        data["event_type"] = "FAILED_LOGIN"

    elif "accepted password" in message_lower:
        data["event_type"] = "SUCCESSFUL_LOGIN"

    elif "invalid user" in message_lower:
        data["event_type"] = "INVALID_USER"

    elif "authentication failure" in message_lower:
        data["event_type"] = "AUTH_FAILURE"

    else:
        data["event_type"] = "OTHER"

    return data


def parse_log_file(file_path):
    """
    Parse an entire log file and return structured events.
    """

    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)

            if parsed:
                events.append(parsed)

    return events