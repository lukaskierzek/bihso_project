from pathlib import Path

import pandas as pd


def load_labels(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Labels file not found: {path}")

    labels = pd.read_csv(path)
    required_columns = {"record_index", "label", "scenario"}
    missing_columns = required_columns - set(labels.columns)

    if missing_columns:
        raise ValueError(f"Missing label columns: {sorted(missing_columns)}")

    labels["record_index"] = labels["record_index"].astype(int)
    labels["label"] = labels["label"].astype(int)

    return labels


def labels_to_series(labels: pd.DataFrame, record_count: int) -> pd.Series:
    y_true = pd.Series(0, index=range(record_count), name="label")

    for row in labels.itertuples(index=False):
        if 0 <= row.record_index < record_count:
            y_true.loc[row.record_index] = int(row.label)

    return y_true
