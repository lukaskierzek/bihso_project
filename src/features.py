from collections import defaultdict, deque

import pandas as pd

from config import FAILED_LOGIN_WINDOW_SECONDS, NIGHT_ACTIVITY_END, NIGHT_ACTIVITY_START
from src.log_record import LogRecord

FAILED_EVENT_TYPES = {"ssh_failed_password", "ssh_invalid_user", "authentication_failure"}
SSH_EVENT_TYPES = {"ssh_login_success", "ssh_failed_password", "ssh_invalid_user", "authentication_failure", "ssh_disconnect"}


def _stable_text_code(value: str | None) -> int:
    if value is None:
        return -1
    return sum(ord(character) for character in value) % 1000


def _is_night(record: LogRecord) -> int:
    if record.timestamp is None:
        return 0
    hour = record.timestamp.hour
    return int(hour >= NIGHT_ACTIVITY_START or hour < NIGHT_ACTIVITY_END)


def _rolling_failed_counts(records: list[LogRecord]) -> list[int]:
    windows: dict[str, deque] = defaultdict(deque)
    counts: list[int] = []

    for record in records:
        key = record.ip_address or record.user or "unknown"
        current_time = record.timestamp
        window = windows[key]

        if current_time is not None:
            while window and (current_time - window[0]).total_seconds() > FAILED_LOGIN_WINDOW_SECONDS:
                window.popleft()

        count = len(window)
        if record.event_type in FAILED_EVENT_TYPES and current_time is not None:
            window.append(current_time)
            count += 1

        counts.append(count)

    return counts


def records_to_features(records: list[LogRecord]) -> pd.DataFrame:
    failed_counts = _rolling_failed_counts(records)
    rows = []

    for record, failed_count in zip(records, failed_counts):
        timestamp = record.timestamp
        command = record.command or ""
        user = record.user or ""
        service = (record.service or "").lower()

        rows.append({
            "hour": timestamp.hour if timestamp else -1,
            "day_of_week": timestamp.weekday() if timestamp else -1,
            "is_weekend": int(timestamp.weekday() >= 5) if timestamp else 0,
            "is_night": _is_night(record),
            "service_code": _stable_text_code(service),
            "event_type_code": _stable_text_code(record.event_type),
            "user_length": len(user),
            "is_root_user": int(user == "root" or record.target_user == "root"),
            "has_ip": int(record.ip_address is not None),
            "ip_code": _stable_text_code(record.ip_address),
            "port": record.port if record.port is not None else 0,
            "success": int(record.success) if record.success is not None else -1,
            "is_ssh_event": int(record.event_type in SSH_EVENT_TYPES or service.startswith("sshd")),
            "is_failed_login": int(record.event_type in FAILED_EVENT_TYPES),
            "is_invalid_user": int(record.event_type == "ssh_invalid_user"),
            "is_sudo": int(service == "sudo" or record.event_type.startswith("sudo")),
            "is_cron": int(service == "cron" or record.event_type.startswith("cron")),
            "command_length": len(command),
            "failed_login_count_window": failed_count,
            "raw_message_length": len(record.raw_message),
        })

    return pd.DataFrame(rows)
