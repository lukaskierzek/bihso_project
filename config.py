from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

RAW_LOG_PATH = BASE_DIR / "data/raw/auditd_sample.log"

SUSPICIOUS_COMMANDS = [
    "hydra",
    "nmap",
    "nc",
    "netcat",
]

KNOWN_COMMANDS = [
    "ls",
    "cat",
    "nano",
    "vim",
    "bash",
    "python3",
    "grep",
    "find",
    "sudo",
    "ssh",
    "apt",
    "systemctl",
    "pwd",
    "whoami",
    "id",
]

NIGHT_ACTIVITY_START = 22
NIGHT_ACTIVITY_END = 5

ISOLATION_FOREST_CONTAMINATION = 0.05
RANDOM_STATE = 42