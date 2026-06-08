import re
from datetime import datetime

from src.log_record import LogRecord

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<service>[^:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_PATTERN = re.compile(r"\bport\s+(\d+)\b")
ACCEPTED_PATTERN = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
FAILED_PATTERN = re.compile(r"Failed \S+ for (?:(?:invalid user) )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
INVALID_USER_PATTERN = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
AUTH_FAILURE_USER_PATTERN = re.compile(r"\buser=(?P<user>\S+)")
SESSION_USER_PATTERN = re.compile(r"session (?P<state>opened|closed) for user (?P<user>[^\s(]+)")
SESSION_BY_PATTERN = re.compile(r"\bby (?P<source>[^\s(]+)")
SUDO_COMMAND_PATTERN = re.compile(r"^(?P<source>\S+)\s+:.*\bUSER=(?P<target>\S+)\s+;\s+COMMAND=(?P<command>.*)$")
PASSWORD_CHANGE_PATTERN = re.compile(r"password for '(?P<user>[^']+)' changed by '(?P<source>[^']+)'")
NEW_SESSION_PATTERN = re.compile(r"New session '.*' of user '(?P<user>[^']+)'")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _first_ip(message: str) -> str | None:
    match = IP_PATTERN.search(message)
    return match.group(0) if match else None


def _first_port(message: str) -> int | None:
    match = PORT_PATTERN.search(message)
    return int(match.group(1)) if match else None


def _base_record(line: str, event_type: str = "other", success: bool | None = None) -> LogRecord:
    match = SYSLOG_PATTERN.match(line.strip())
    if match is None:
        return LogRecord(
            timestamp=None,
            hostname=None,
            service=None,
            process_id=None,
            event_type="unparsed",
            user=None,
            target_user=None,
            source_user=None,
            ip_address=None,
            port=None,
            command=None,
            success=None,
            raw_event=line.strip(),
            raw_message=line.strip(),
        )

    message = match.group("message")
    return LogRecord(
        timestamp=_parse_timestamp(match.group("timestamp")),
        hostname=match.group("hostname"),
        service=match.group("service"),
        process_id=match.group("pid"),
        event_type=event_type,
        user=None,
        target_user=None,
        source_user=None,
        ip_address=_first_ip(message),
        port=_first_port(message),
        command=None,
        success=success,
        raw_event=message,
        raw_message=line.strip(),
    )


def parse_line(line: str) -> LogRecord:
    record = _base_record(line)
    message = record.raw_event
    lowered = message.lower()

    accepted = ACCEPTED_PATTERN.search(message)
    if accepted:
        record.event_type = "ssh_login_success"
        record.user = accepted.group("user")
        record.ip_address = accepted.group("ip")
        record.port = int(accepted.group("port"))
        record.success = True
        return record

    invalid = INVALID_USER_PATTERN.search(message)
    if invalid:
        record.event_type = "ssh_invalid_user"
        record.user = invalid.group("user")
        record.ip_address = invalid.group("ip")
        record.port = int(invalid.group("port"))
        record.success = False
        return record

    failed = FAILED_PATTERN.search(message)
    if failed:
        record.event_type = "ssh_failed_password"
        record.user = failed.group("user")
        record.ip_address = failed.group("ip")
        record.port = int(failed.group("port"))
        record.success = False
        return record

    if "authentication failure" in lowered:
        user = AUTH_FAILURE_USER_PATTERN.search(message)
        record.event_type = "authentication_failure"
        record.user = user.group("user") if user else None
        record.success = False
        return record

    sudo_command = SUDO_COMMAND_PATTERN.search(message)
    if sudo_command and (record.service or "").lower() == "sudo":
        record.event_type = "sudo_command"
        record.source_user = sudo_command.group("source")
        record.user = sudo_command.group("source")
        record.target_user = sudo_command.group("target")
        record.command = sudo_command.group("command").strip()
        record.success = True
        return record

    session = SESSION_USER_PATTERN.search(message)
    if session:
        service = (record.service or "").lower()
        state = session.group("state")
        record.event_type = f"session_{state}"
        if service == "cron":
            record.event_type = f"cron_session_{state}"
        elif service == "sudo":
            record.event_type = f"sudo_session_{state}"
        record.user = session.group("user")
        by = SESSION_BY_PATTERN.search(message)
        record.source_user = by.group("source") if by else None
        record.success = True
        return record

    password_change = PASSWORD_CHANGE_PATTERN.search(message)
    if password_change:
        record.event_type = "password_changed"
        record.user = password_change.group("user")
        record.source_user = password_change.group("source")
        record.success = True
        return record

    new_session = NEW_SESSION_PATTERN.search(message)
    if new_session:
        record.event_type = "systemd_new_session"
        record.user = new_session.group("user")
        record.success = True
        return record

    if "server listening" in lowered:
        record.event_type = "ssh_server_listening"
        record.success = True
    elif "disconnect" in lowered or "connection closed" in lowered or "closed by" in lowered:
        record.event_type = "ssh_disconnect"
        record.success = None
    elif "unable to locate package" in lowered:
        record.event_type = "package_error"
        record.success = False
    elif "reboot" in lowered or "system is rebooting" in lowered:
        record.event_type = "system_reboot"
        record.success = True

    return record


def parse_lines(lines: list[str]) -> list[LogRecord]:
    return [parse_line(line) for line in lines if line.strip()]


def parse_lines_grouped(lines: list[str]) -> list[LogRecord]:
    return parse_lines(lines)
