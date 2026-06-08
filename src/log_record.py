from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogRecord:
    timestamp: datetime | None
    hostname: str | None
    service: str | None
    process_id: str | None
    event_type: str
    user: str | None
    target_user: str | None
    source_user: str | None
    ip_address: str | None
    port: int | None
    command: str | None
    success: bool | None
    raw_event: str
    raw_message: str

    @property
    def has_ip(self) -> bool:
        return self.ip_address is not None

    @property
    def is_root_login(self) -> bool:
        return self.user == "root" and self.event_type in {
            "ssh_login_success",
            "ssh_failed_password",
            "ssh_invalid_user",
            "authentication_failure",
        }
