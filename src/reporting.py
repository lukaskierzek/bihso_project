from src.log_record import LogRecord
from src.rules import DetectionResult


def print_detection_results(
    record: LogRecord,
    detections: list[DetectionResult]
) -> None:

    if not detections:
        return

    print("=" * 80)
    print(f"Timestamp: {record.timestamp}")
    print(record.raw_message)
    print()

    for detection in detections:
        print(detection)

    print()