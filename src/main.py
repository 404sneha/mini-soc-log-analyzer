import json

from parser import parse_log_file
from detector import (
    detect_ssh_brute_force,
    detect_invalid_users,
    detect_success_after_failures
)
from risk_engine import enrich_alert


LOG_FILE = "sample_logs/auth.log"


def main():
    print("=" * 60)
    print("MINI SOC LOG ANALYZER")
    print("=" * 60)

    print("\n[1] Parsing authentication logs...")

    events = parse_log_file(LOG_FILE)

    print(f"[+] Parsed events: {len(events)}")

    print("\n[2] Running security detection rules...")

    alerts = []

    # Detection Rule 1: SSH brute force
    alerts.extend(
        detect_ssh_brute_force(events)
    )

    # Detection Rule 2: Invalid-user enumeration
    alerts.extend(
        detect_invalid_users(events)
    )

    # Detection Rule 3: Successful login after multiple failures
    alerts.extend(
        detect_success_after_failures(events)
    )

    print(f"[+] Alerts detected: {len(alerts)}")

    print("\n[3] Calculating risk scores...")

    enriched_alerts = [
        enrich_alert(alert)
        for alert in alerts
    ]

    if not enriched_alerts:
        print("\n[+] No suspicious activity detected.")

    else:
        print("\n" + "=" * 60)
        print("SECURITY ALERTS")
        print("=" * 60)

        for alert in enriched_alerts:
            print(f"\nAlert Type: {alert['alert_type']}")
            print(f"Severity: {alert['severity']}")
            print(f"Risk Score: {alert['risk_score']}")
            print(f"Risk Category: {alert['risk_category']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Failed Attempts: {alert['failed_attempts']}")
            print(f"Description: {alert['description']}")

    # Save alerts to JSON report
    report_path = "reports/alerts.json"

    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(enriched_alerts, report_file, indent=4)

    print(f"\n[+] Report saved to: {report_path}")

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()