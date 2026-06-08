from dataclasses import dataclass

from config import (
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_SECONDS,
    NIGHT_ACTIVITY_END,
    NIGHT_ACTIVITY_START,
)
from src.log_record import LogRecord


@dataclass
class DetectionResult:
    rule_name: str
    is_anomaly: bool
    reason: str

    def __str__(self) -> str:
        return f"[ALERT] {self.rule_name}: {self.reason}"


def _result(rule_name: str, reason: str = "") -> DetectionResult:
    return DetectionResult(rule_name=rule_name, is_anomaly=bool(reason), reason=reason)


def detect_failed_password(record: LogRecord) -> DetectionResult:
    if record.event_type == "ssh_failed_password":
        return _result("Failed password", f"Failed SSH password for user={record.user} from ip={record.ip_address}")
    return _result("Failed password")


def detect_invalid_user(record: LogRecord) -> DetectionResult:
    if record.event_type == "ssh_invalid_user":
        return _result("Invalid user", f"Login attempt for non-existing user={record.user} from ip={record.ip_address}")
    return _result("Invalid user")


def detect_authentication_failure(record: LogRecord) -> DetectionResult:
    if record.event_type == "authentication_failure":
        return _result("Authentication failure", f"PAM authentication failure for user={record.user} from ip={record.ip_address}")
    return _result("Authentication failure")


def detect_root_login(record: LogRecord) -> DetectionResult:
    if record.user == "root" and record.event_type in {"ssh_login_success", "ssh_failed_password", "ssh_invalid_user", "authentication_failure"}:
        return _result("Root login", f"Root authentication event type={record.event_type} from ip={record.ip_address}")
    return _result("Root login")


def detect_night_activity(record: LogRecord) -> DetectionResult:
    if record.timestamp is None:
        return _result("Unusual hour")

    hour = record.timestamp.hour
    is_night = hour >= NIGHT_ACTIVITY_START or hour < NIGHT_ACTIVITY_END
    is_interesting = record.event_type in {
        "ssh_login_success",
        "ssh_failed_password",
        "ssh_invalid_user",
        "authentication_failure",
        "sudo_command",
        "password_changed",
    }

    if is_night and is_interesting:
        return _result("Unusual hour", f"Security-relevant event at unusual hour={hour}")
    return _result("Unusual hour")


def detect_sudo_usage(record: LogRecord) -> DetectionResult:
    if record.event_type == "sudo_command":
        return _result("Sudo usage", f"sudo by {record.source_user} as {record.target_user}: {record.command}")
    return _result("Sudo usage")


def detect_password_change(record: LogRecord) -> DetectionResult:
    if record.event_type == "password_changed" and record.source_user != record.user:
        return _result("Password change", f"Password for {record.user} changed by {record.source_user}")
    return _result("Password change")


def run_all_rules(record: LogRecord) -> list[DetectionResult]:
    results = [
        detect_failed_password(record),
        detect_invalid_user(record),
        detect_authentication_failure(record),
        detect_root_login(record),
        detect_night_activity(record),
        detect_sudo_usage(record),
        detect_password_change(record),
    ]
    return [result for result in results if result.is_anomaly]


def detect_brute_force(record: LogRecord, previous_records: list[LogRecord]) -> DetectionResult:
    if record.timestamp is None or record.ip_address is None:
        return _result("Brute-force SSH")

    if record.event_type not in {"ssh_failed_password", "ssh_invalid_user", "authentication_failure"}:
        return _result("Brute-force SSH")

    failures = [
        previous
        for previous in previous_records
        if previous.timestamp is not None
        and previous.ip_address == record.ip_address
        and previous.event_type in {"ssh_failed_password", "ssh_invalid_user", "authentication_failure"}
        and 0 <= (record.timestamp - previous.timestamp).total_seconds() <= FAILED_LOGIN_WINDOW_SECONDS
    ]

    failure_count = len(failures) + 1
    if failure_count >= FAILED_LOGIN_THRESHOLD:
        return _result(
            "Brute-force SSH",
            f"{failure_count} failed SSH/auth events from ip={record.ip_address} within {FAILED_LOGIN_WINDOW_SECONDS}s",
        )
    return _result("Brute-force SSH")


def run_all_rules_with_context(records: list[LogRecord]) -> list[list[DetectionResult]]:
    all_results: list[list[DetectionResult]] = []

    for index, record in enumerate(records):
        detections = run_all_rules(record)
        brute_force = detect_brute_force(record, records[:index])
        if brute_force.is_anomaly:
            detections.append(brute_force)
        all_results.append(detections)

    return all_results
