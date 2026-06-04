from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

RAW_LOG_PATH = BASE_DIR / "data/raw/auditd_sample.log"
LABELS_PATH = BASE_DIR / "data/labels.csv"

SUSPICIOUS_COMMANDS = [
    "hydra",
    "nmap",
    "nc",
    "netcat",
]

ADMIN_COMMANDS = [
    "sudo",
    "su",
    "chmod",
    "chown",
    "usermod",
    "useradd",
    "passwd",
    "iptables",
    "systemctl",
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
    "chmod",
    "rm",
    "curl",
    "su",
    "iptables",
]

NIGHT_ACTIVITY_START = 22
NIGHT_ACTIVITY_END = 5

SUSPICIOUS_PATH_PREFIXES = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]

TRUSTED_EXECUTABLE_PREFIXES = [
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
]

FAILED_OPERATION_WINDOW_SECONDS = 300
FAILED_OPERATION_THRESHOLD = 3

ISOLATION_FOREST_CONTAMINATION = 0.05
LOCAL_OUTLIER_FACTOR_CONTAMINATION = 0.05
RANDOM_STATE = 42
