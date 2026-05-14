from src.rules import DetectionResult


def print_detection_results(detections: list[DetectionResult]) -> None:
    if not detections:
        return

    print("=" * 80)

    for detection in detections:
        print(detection)

    print()
