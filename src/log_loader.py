from pathlib import Path


def load_logs(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    with open(path, 'r', encoding="utf-8") as file:
        return file.readlines()
