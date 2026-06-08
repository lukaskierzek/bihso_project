from collections import Counter

import pandas as pd

from src.log_record import LogRecord
from src.rules import run_all_rules_with_context

ANOMALY_EVENT_TYPES = {
    "ssh_failed_password",
    "ssh_invalid_user",
    "authentication_failure",
    "package_error",
}
NORMAL_EVENT_TYPES = {
    "ssh_login_success",
    "sudo_command",
    "sudo_session_opened",
    "sudo_session_closed",
    "session_opened",
    "session_closed",
    "cron_session_opened",
    "cron_session_closed",
    "systemd_new_session",
    "ssh_server_listening",
}


def records_to_dataframe(records: list[LogRecord]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "timestamp": record.timestamp,
            "hostname": record.hostname,
            "service": record.service,
            "process_id": record.process_id,
            "event_type": record.event_type,
            "user": record.user,
            "target_user": record.target_user,
            "source_user": record.source_user,
            "ip_address": record.ip_address,
            "port": record.port,
            "command": record.command,
            "success": record.success,
            "raw_event": record.raw_event,
        }
        for record in records
    ])


def auto_label_records(records: list[LogRecord]) -> pd.Series:
    detections_by_record = run_all_rules_with_context(records)
    labels = []

    for record, detections in zip(records, detections_by_record):
        rule_names = {detection.rule_name for detection in detections}
        is_anomaly = (
            record.event_type in ANOMALY_EVENT_TYPES
            or "Brute-force SSH" in rule_names
            or (record.event_type == "ssh_login_success" and record.user == "root")
        )
        labels.append(1 if is_anomaly else 0)

    return pd.Series(labels, name="anomaly")


def calculate_detection_statistics(records: list[LogRecord]) -> dict:
    detections_by_record = run_all_rules_with_context(records)
    rule_counter = Counter(
        detection.rule_name
        for detections in detections_by_record
        for detection in detections
    )
    anomaly_logs = sum(1 for detections in detections_by_record if detections)

    return {
        "total_logs": len(records),
        "anomaly_logs": anomaly_logs,
        "normal_logs": len(records) - anomaly_logs,
        "rule_counter": dict(rule_counter),
    }


def detections_to_dataframe(records: list[LogRecord]) -> pd.DataFrame:
    rows = []
    detections_by_record = run_all_rules_with_context(records)

    for index, (record, detections) in enumerate(zip(records, detections_by_record)):
        for detection in detections:
            rows.append({
                "record_index": index,
                "timestamp": record.timestamp,
                "service": record.service,
                "event_type": record.event_type,
                "user": record.user,
                "ip_address": record.ip_address,
                "rule": detection.rule_name,
                "reason": detection.reason,
            })

    return pd.DataFrame(rows)


def get_rule_anomaly_indices(records: list[LogRecord]) -> set[int]:
    return {
        index
        for index, detections in enumerate(run_all_rules_with_context(records))
        if detections
    }


def compare_detection_methods(records: list[LogRecord], isolation_predictions, lof_predictions) -> pd.DataFrame:
    rule_indices = get_rule_anomaly_indices(records)
    isolation_indices = {index for index, prediction in enumerate(isolation_predictions) if prediction == -1}
    lof_indices = {index for index, prediction in enumerate(lof_predictions) if prediction == -1}

    rows = []
    for method_name, indices in {
        "Rule-based": rule_indices,
        "Isolation Forest": isolation_indices,
        "Local Outlier Factor": lof_indices,
    }.items():
        rows.append({
            "method": method_name,
            "detected_anomalies": len(indices),
            "percentage": round(len(indices) / len(records) * 100, 2) if records else 0,
            "overlap_with_rules": len(indices & rule_indices),
        })

    return pd.DataFrame(rows)


def _calculate_binary_metrics(y_true: list[int], y_pred: list[int], method_name: str) -> dict:
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


def calculate_labeled_metrics(records: list[LogRecord], labels, isolation_predictions, lof_predictions) -> pd.DataFrame:
    y_true = list(pd.Series(labels).astype(int))
    rule_indices = get_rule_anomaly_indices(records)
    predictions = {
        "Rule-based": [1 if index in rule_indices else 0 for index in range(len(records))],
        "Isolation Forest": [1 if prediction == -1 else 0 for prediction in isolation_predictions],
        "Local Outlier Factor": [1 if prediction == -1 else 0 for prediction in lof_predictions],
    }
    return pd.DataFrame([
        _calculate_binary_metrics(y_true, y_pred, method_name)
        for method_name, y_pred in predictions.items()
    ])


def confusion_matrices(records: list[LogRecord], labels, isolation_predictions, lof_predictions) -> dict[str, pd.DataFrame]:
    metrics = calculate_labeled_metrics(records, labels, isolation_predictions, lof_predictions)
    matrices = {}
    for row in metrics.itertuples(index=False):
        matrices[row.method] = pd.DataFrame(
            [[row.tn, row.fp], [row.fn, row.tp]],
            index=["actual_0", "actual_1"],
            columns=["pred_0", "pred_1"],
        )
    return matrices
