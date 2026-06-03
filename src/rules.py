from dataclasses import dataclass

from config import (
    ADMIN_COMMANDS,
    FAILED_OPERATION_THRESHOLD,
    FAILED_OPERATION_WINDOW_SECONDS,
    SUSPICIOUS_COMMANDS,
    NIGHT_ACTIVITY_START,
    NIGHT_ACTIVITY_END,
    KNOWN_COMMANDS,
    SUSPICIOUS_PATH_PREFIXES,
    TRUSTED_EXECUTABLE_PREFIXES,
)
from src.log_record import LogRecord


@dataclass
class DetectionResult:
    rule_name: str
    is_anomaly: bool
    reason: str

    def __str__(self) -> str:
        return f"[ALERT] {self.rule_name}: {self.reason}"


def detect_suspicious_command(record: LogRecord) -> DetectionResult:
    if record.command in SUSPICIOUS_COMMANDS:
        return DetectionResult(
            rule_name="Suspicious Command",
            is_anomaly=True,
            reason=f"Detected suspicious command: {record.command}"
        )

    return DetectionResult(
        rule_name="Suspicious Command",
        is_anomaly=False,
        reason=""
    )


def detect_root_activity(record: LogRecord) -> DetectionResult:
    if record.user_id == "0":
        return DetectionResult(
            rule_name="Root Activity",
            is_anomaly=True,
            reason="Root user activity detected"
        )

    return DetectionResult(
        rule_name="Root Activity",
        is_anomaly=False,
        reason=""
    )


def detect_failed_command(record: LogRecord) -> DetectionResult:
    if record.success is False:
        return DetectionResult(
            rule_name="Failed Command",
            is_anomaly=True,
            reason="Command execution failed"
        )

    return DetectionResult(
        rule_name="Failed Command",
        is_anomaly=False,
        reason=""
    )


def detect_night_activity(record: LogRecord) -> DetectionResult:
    if record.timestamp is None:
        return DetectionResult(
            rule_name="Night Activity",
            is_anomaly=False,
            reason=""
        )

    hour = record.timestamp.hour
    is_night: bool = (hour >= NIGHT_ACTIVITY_START or hour < NIGHT_ACTIVITY_END)

    if is_night:
        return DetectionResult(
            rule_name="Night Activity",
            is_anomaly=True,
            reason=f"Activity detected at unusual hour: {hour}"
        )

    return DetectionResult(
        rule_name="Night Activity",
        is_anomaly=False,
        reason=""
    )

def detect_unknown_command(record: LogRecord) -> DetectionResult:

    if record.command is None:
        return DetectionResult(
            rule_name="Unknown Command",
            is_anomaly=False,
            reason=""
        )

    if record.command not in KNOWN_COMMANDS:

        return DetectionResult(
            rule_name="Unknown Command",
            is_anomaly=True,
            reason=f"Unknown command detected: {record.command}"
        )

    return DetectionResult(
        rule_name="Unknown Command",
        is_anomaly=False,
        reason=""
    )


def detect_suspicious_executable_path(record: LogRecord) -> DetectionResult:
    checked_paths = [
        path
        for path in [record.executable, record.path]
        if path
    ]

    for path in checked_paths:
        if any(path.startswith(prefix) for prefix in SUSPICIOUS_PATH_PREFIXES):
            return DetectionResult(
                rule_name="Suspicious Executable Path",
                is_anomaly=True,
                reason=f"Suspicious path used: {path}"
            )

    if record.executable and not any(
        record.executable.startswith(prefix)
        for prefix in TRUSTED_EXECUTABLE_PREFIXES
    ):
        return DetectionResult(
            rule_name="Suspicious Executable Path",
            is_anomaly=True,
            reason=f"Executable outside trusted paths: {record.executable}"
        )

    return DetectionResult(
        rule_name="Suspicious Executable Path",
        is_anomaly=False,
        reason=""
    )


def detect_admin_tool(record: LogRecord) -> DetectionResult:
    if record.command in ADMIN_COMMANDS:
        return DetectionResult(
            rule_name="Administrative Tool",
            is_anomaly=True,
            reason=f"Administrative tool executed: {record.command}"
        )

    return DetectionResult(
        rule_name="Administrative Tool",
        is_anomaly=False,
        reason=""
    )


def detect_unusual_uid(record: LogRecord) -> DetectionResult:
    unusual_values = {"4294967295", "65534"}

    if record.user_id in unusual_values or record.audit_user_id in unusual_values:
        return DetectionResult(
            rule_name="Unusual UID",
            is_anomaly=True,
            reason=f"Unusual uid/auid combination: uid={record.user_id}, auid={record.audit_user_id}"
        )

    if record.user_id == "0" and record.audit_user_id not in (None, "0"):
        return DetectionResult(
            rule_name="Unusual UID",
            is_anomaly=True,
            reason=f"Root effective UID with non-root auid: auid={record.audit_user_id}"
        )

    return DetectionResult(
        rule_name="Unusual UID",
        is_anomaly=False,
        reason=""
    )


def detect_unusual_event_combination(record: LogRecord) -> DetectionResult:
    is_failed_root = record.user_id == "0" and record.success is False
    is_admin_at_night = (
        record.command in ADMIN_COMMANDS
        and record.timestamp is not None
        and (record.timestamp.hour >= NIGHT_ACTIVITY_START or record.timestamp.hour < NIGHT_ACTIVITY_END)
    )

    if is_failed_root:
        return DetectionResult(
            rule_name="Unusual Event Combination",
            is_anomaly=True,
            reason="Failed operation executed with root UID"
        )

    if is_admin_at_night:
        return DetectionResult(
            rule_name="Unusual Event Combination",
            is_anomaly=True,
            reason=f"Administrative command at unusual hour: {record.command}"
        )

    return DetectionResult(
        rule_name="Unusual Event Combination",
        is_anomaly=False,
        reason=""
    )


def run_all_rules(record: LogRecord) -> list[DetectionResult]:
    results = [
        detect_suspicious_command(record),
        detect_root_activity(record),
        detect_failed_command(record),
        detect_night_activity(record),
        detect_unknown_command(record),
        detect_suspicious_executable_path(record),
        detect_admin_tool(record),
        detect_unusual_uid(record),
        detect_unusual_event_combination(record),
    ]

    return [result for result in results if result.is_anomaly]


def detect_repeated_failed_operations(
    record: LogRecord,
    previous_records: list[LogRecord]
) -> DetectionResult:
    if record.timestamp is None or record.success is not False:
        return DetectionResult(
            rule_name="Repeated Failed Operations",
            is_anomaly=False,
            reason=""
        )

    failures = [
        previous
        for previous in previous_records
        if previous.timestamp is not None
        and previous.success is False
        and previous.user_id == record.user_id
        and 0 <= (record.timestamp - previous.timestamp).total_seconds() <= FAILED_OPERATION_WINDOW_SECONDS
    ]

    if len(failures) + 1 >= FAILED_OPERATION_THRESHOLD:
        return DetectionResult(
            rule_name="Repeated Failed Operations",
            is_anomaly=True,
            reason=(
                f"{len(failures) + 1} failed operations by uid={record.user_id} "
                f"within {FAILED_OPERATION_WINDOW_SECONDS} seconds"
            )
        )

    return DetectionResult(
        rule_name="Repeated Failed Operations",
        is_anomaly=False,
        reason=""
    )


def run_all_rules_with_context(records: list[LogRecord]) -> list[list[DetectionResult]]:
    all_results: list[list[DetectionResult]] = []

    for index, record in enumerate(records):
        detections = run_all_rules(record)
        repeated_failures = detect_repeated_failed_operations(
            record,
            records[:index]
        )

        if repeated_failures.is_anomaly:
            detections.append(repeated_failures)

        all_results.append(detections)

    return all_results
