from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogRecord:
    timestamp: datetime | None
    event_type: str | None
    user_id: str | None
    command: str | None
    executable: str | None
    success: bool | None
    raw_message: str
