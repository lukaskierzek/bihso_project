from collections import Counter

import pandas as pd

from config import SUSPICIOUS_COMMANDS
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

def calculate_baseline_metrics(
        records: list[LogRecord]
) -> dict:

    CHECKED_COMMANDS = SUSPICIOUS_COMMANDS

    tp = fp = tn = fn = 0

    for record in records:

        expected = record.command in CHECKED_COMMANDS

        predicted = bool(run_all_rules(record))

        if expected and predicted:
            tp += 1

        elif expected and not predicted:
            fn += 1

        elif not expected and predicted:
            fp += 1

        else:
            tn += 1

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0
    )

    accuracy = (
        (tp + tn) / (tp + tn + fp + fn)
        if (tp + tn + fp + fn) > 0
        else 0
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2),
    }