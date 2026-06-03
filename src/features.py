import pandas as pd

from config import ADMIN_COMMANDS, SUSPICIOUS_COMMANDS, SUSPICIOUS_PATH_PREFIXES
from src.log_record import LogRecord


def _to_int(value: str | None, default: int = -1) -> int:
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        return default


def _has_suspicious_path(record: LogRecord) -> int:
    paths = [
        path
        for path in [record.executable, record.path, record.cwd]
        if path
    ]

    return int(any(
        path.startswith(prefix)
        for path in paths
        for prefix in SUSPICIOUS_PATH_PREFIXES
    ))


def _stable_text_code(value: str | None) -> int:
    if value is None:
        return -1

    return sum(ord(character) for character in value) % 100


def records_to_features(
        records: list[LogRecord]
) -> pd.DataFrame:

    rows = []

    for record in records:

        rows.append({
            "hour":
                record.timestamp.hour
                if record.timestamp
                else -1,

            "is_root":
                1 if record.user_id == "0" else 0,

            "success":
                int(record.success)
                if record.success is not None
                else 0,

            "is_night":
                1 if (record.timestamp and (record.timestamp.hour >= 22 or record.timestamp.hour < 5))
                else 0,

            "is_suspicious_command":
                1 if record.command in SUSPICIOUS_COMMANDS else 0,

            "is_admin_tool":
                1 if record.command in ADMIN_COMMANDS else 0,

            "is_unknown_command":
                1 if record.command is None else 0,

            "has_executable":
                1 if record.executable else 0,

            "has_path":
                1 if record.path else 0,

            "has_suspicious_path":
                _has_suspicious_path(record),

            "uid":
                _to_int(record.user_id),

            "auid":
                _to_int(record.audit_user_id),

            "uid_mismatch":
                1 if (
                    record.user_id is not None
                    and record.audit_user_id is not None
                    and record.user_id != record.audit_user_id
                ) else 0,

            "event_type_code":
                _stable_text_code(record.event_type),

            "command_length":
                len(record.command) if record.command else 0,

            "raw_message_length":
                len(record.raw_message),
        })

    return pd.DataFrame(rows)
