import re

from src.log_record import LogRecord

TYPE_PATTERN = re.compile(r"type=([A-Z_]+)")
UID_PATTERN = re.compile(r"uid=(\d+)")
COMM_PATTERN = re.compile(r'comm="([^"]+)"')
EXE_PATTERN = re.compile(r'exe="([^"]+)"')
SUCCESS_PATTERN = re.compile(r"success=(yes|no)")


def _extract(pattern: re.Pattern, line: str) -> str | None:
    match = pattern.search(line)
    if match:
        return match.group(1)
    return None


def _parse_success(value: str | None) -> bool | None:
    if value is None:
        return None
    return {"yes": True, "no": False}.get(value)


def parse_line(line: str) -> LogRecord:
    event_type = _extract(TYPE_PATTERN, line)
    user_id = _extract(UID_PATTERN, line)
    command = _extract(COMM_PATTERN, line)
    executable = _extract(EXE_PATTERN, line)
    success_raw = _extract(SUCCESS_PATTERN, line)

    return LogRecord(
        timestamp=None,
        event_type=event_type,
        user_id=user_id,
        command=command,
        executable=executable,
        success=_parse_success(success_raw),
        raw_message=line.strip()
    )
