import re
from datetime import datetime

from src.log_record import LogRecord

TYPE_PATTERN = re.compile(r"type=([A-Z_]+)")
UID_PATTERN = re.compile(r"uid=(\d+)")
AUID_PATTERN = re.compile(r"auid=(\d+)")
PID_PATTERN = re.compile(r"pid=(\d+)")
COMM_PATTERN = re.compile(r'comm="([^"]+)"')
EXE_PATTERN = re.compile(r'exe="([^"]+)"')
AUDIT_PATTERN = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
PATH_PATTERN = re.compile(r'name="([^"]+)"')
CWD_PATTERN = re.compile(r'cwd="([^"]+)"')
USER_CMD_PATTERN = re.compile(r'cmd="([^"]+)"')
EXECVE_ARG0_PATTERN = re.compile(r'a0="([^"]+)"')

SUCCESS_PATTERN = re.compile(r"success=(yes|no)")
RESULT_PATTERN = re.compile(r"res=(success|failed)")


def _extract(pattern: re.Pattern, line: str) -> str | None:
    match = pattern.search(line)
    if match:
        return match.group(1)
    return None


def _parse_success(
        success_value: str | None,
        result_value: str | None
) -> bool | None:
    if success_value is not None:
        return {"yes": True, "no": False}.get(success_value)

    if result_value is not None:
        return {"success": True, "failed": False}.get(result_value)

    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value))


def _extract_audit_metadata(line: str) -> tuple[datetime | None, str | None]:
    match = AUDIT_PATTERN.search(line)
    if match is None:
        return None, None

    return _parse_timestamp(match.group(1)), match.group(2)


def _parse_command(line: str) -> str | None:
    command = _extract(COMM_PATTERN, line)
    if command is not None:
        return command

    user_cmd = _extract(USER_CMD_PATTERN, line)
    if user_cmd is not None:
        return user_cmd.split()[0]

    return _extract(EXECVE_ARG0_PATTERN, line)


def parse_line(line: str) -> LogRecord:
    event_type = _extract(TYPE_PATTERN, line)
    user_id = _extract(UID_PATTERN, line)
    audit_user_id = _extract(AUID_PATTERN, line)
    process_id = _extract(PID_PATTERN, line)
    command = _parse_command(line)
    executable = _extract(EXE_PATTERN, line)
    timestamp, audit_id = _extract_audit_metadata(line)
    success_raw = _extract(SUCCESS_PATTERN, line)
    result_raw = _extract(RESULT_PATTERN, line)

    return LogRecord(
        timestamp=timestamp,
        audit_id=audit_id,
        event_type=event_type,
        user_id=user_id,
        audit_user_id=audit_user_id,
        process_id=process_id,
        command=command,
        executable=executable,
        path=_extract(PATH_PATTERN, line),
        cwd=_extract(CWD_PATTERN, line),
        success=_parse_success(success_raw, result_raw),
        raw_message=line.strip()
    )
