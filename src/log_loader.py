from pathlib import Path


def load_logs(path: Path) -> list[str]:
    with open(path, 'r', encoding="utf-8") as file:
        return file.readlines()
