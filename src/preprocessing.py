from collections import Counter

import pandas as pd

from src.log_record import LogRecord
from src.rules import run_all_rules


def calculate_detection_statistics(
        records: list[LogRecord]
) -> dict:
    total_logs = len(records)
    anomaly_logs = 0

    rule_counter = Counter()

    for record in records:

        detections = run_all_rules(record)

        if detections:
            anomaly_logs += 1

        for detection in detections:
            rule_counter[detection.rule_name] += 1

    return {
        "total_logs": total_logs,
        "anomaly_logs": anomaly_logs,
        "normal_logs": total_logs - anomaly_logs,
        "rule_counter": dict(rule_counter)
    }


def detections_to_dataframe(
        records: list[LogRecord]
) -> pd.DataFrame:
    rows = []

    for record in records:

        detections = run_all_rules(record)

        for detection in detections:
            rows.append({
                "timestamp": record.timestamp,
                "command": record.command,
                "user_id": record.user_id,
                "rule": detection.rule_name,
                "reason": detection.reason
            })

    return pd.DataFrame(rows)
