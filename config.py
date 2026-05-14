from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

RAW_LOG_PATH = BASE_DIR / "data/raw/auditid_sample.log"

SUSPICIOUS_COMMANDS = [
    "hydra",
    "nmap",
    "nc",
]

NIGHT_ACTIVITY_START = 0
NIGHT_ACTIVITY_END = 5
