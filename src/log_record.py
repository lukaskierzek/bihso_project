from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogRecord:
    timestamp: datetime | None
    audit_id: str | None
    event_type: str | None
    user_id: str | None
    audit_user_id: str | None
    process_id: str | None
    command: str | None
    executable: str | None
    path: str | None
    cwd: str | None
    success: bool | None
    raw_message: str
