from dataclasses import dataclass

from config import (
    SUSPICIOUS_COMMANDS,
    NIGHT_ACTIVITY_START,
    NIGHT_ACTIVITY_END
)
from src.log_record import LogRecord


@dataclass
class DetectionResult:
    rule_name: str
    is_anomaly: bool
    reason: str


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


def detection_night_activity(record: LogRecord) -> DetectionResult:
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


def run_all_rules(record: LogRecord) -> list[DetectionResult]:
    results = [
        detect_suspicious_command(record),
        detect_root_activity(record),
        detect_failed_command(record),
        detection_night_activity(record),
    ]

    return [result for result in results if result.is_anomaly]
