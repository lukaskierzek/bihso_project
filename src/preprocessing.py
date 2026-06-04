from collections import Counter

import pandas as pd

from config import SUSPICIOUS_COMMANDS
from src.log_record import LogRecord
from src.rules import run_all_rules, run_all_rules_with_context


def calculate_detection_statistics(
        records: list[LogRecord]
) -> dict:
    total_logs = len(records)
    anomaly_logs = 0

    rule_counter = Counter()
    detections_by_record = run_all_rules_with_context(records)

    for detections in detections_by_record:

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
    detections_by_record = run_all_rules_with_context(records)

    for record, detections in zip(records, detections_by_record):

        for detection in detections:
            rows.append({
                "timestamp": record.timestamp,
                "command": record.command,
                "user_id": record.user_id,
                "rule": detection.rule_name,
                "reason": detection.reason
            })

    return pd.DataFrame(rows)


def get_rule_anomaly_indices(records: list[LogRecord]) -> set[int]:
    detections_by_record = run_all_rules_with_context(records)

    return {
        index
        for index, detections in enumerate(detections_by_record)
        if detections
    }

def calculate_baseline_metrics(
        records: list[LogRecord]
) -> dict:

    CHECKED_COMMANDS = SUSPICIOUS_COMMANDS

    tp = fp = tn = fn = 0

    for record in records:

        expected = record.command in CHECKED_COMMANDS

        predicted = any(
            detection.rule_name == "Suspicious Command"
            for detection in run_all_rules(record)
        )

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


def compare_detection_methods(
    records: list[LogRecord],
    isolation_predictions,
    lof_predictions
) -> pd.DataFrame:
    rule_indices = get_rule_anomaly_indices(records)
    isolation_indices = {
        index
        for index, prediction in enumerate(isolation_predictions)
        if prediction == -1
    }
    lof_indices = {
        index
        for index, prediction in enumerate(lof_predictions)
        if prediction == -1
    }

    methods = {
        "Rule-based": rule_indices,
        "Isolation Forest": isolation_indices,
        "Local Outlier Factor": lof_indices,
    }

    rows = []
    for method_name, indices in methods.items():
        rows.append({
            "method": method_name,
            "detected_anomalies": len(indices),
            "percentage": round(len(indices) / len(records) * 100, 2) if records else 0,
            "overlap_with_rules": len(indices & rule_indices),
        })

    return pd.DataFrame(rows)


def _calculate_binary_metrics(
    y_true: list[int],
    y_pred: list[int],
    method_name: str
) -> dict:
    tp = fp = tn = fn = 0

    for expected, predicted in zip(y_true, y_pred):
        if expected == 1 and predicted == 1:
            tp += 1
        elif expected == 0 and predicted == 1:
            fp += 1
        elif expected == 0 and predicted == 0:
            tn += 1
        elif expected == 1 and predicted == 0:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0

    return {
        "method": method_name,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2),
    }


def calculate_labeled_metrics(
    records: list[LogRecord],
    labels,
    isolation_predictions,
    lof_predictions
) -> pd.DataFrame:
    y_true = list(labels.astype(int))
    rule_indices = get_rule_anomaly_indices(records)

    predictions = {
        "Rule-based": [
            1 if index in rule_indices else 0
            for index in range(len(records))
        ],
        "Isolation Forest": [
            1 if prediction == -1 else 0
            for prediction in isolation_predictions
        ],
        "Local Outlier Factor": [
            1 if prediction == -1 else 0
            for prediction in lof_predictions
        ],
    }

    rows = [
        _calculate_binary_metrics(y_true, y_pred, method_name)
        for method_name, y_pred in predictions.items()
    ]

    return pd.DataFrame(rows)
