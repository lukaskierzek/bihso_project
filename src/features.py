import pandas as pd

from src.log_record import LogRecord


def records_to_features(
        records: list[LogRecord]
) -> pd.DataFrame:

    rows = []

    for record in records:

        rows.append({
            "hour":
                record.timestamp.hour
                if record.timestamp
                else -1,

            "is_root":
                1 if record.user_id == "0" else 0,

            "success":
                int(record.success)
                if record.success is not None
                else 0,

            "is_night":
                1 if (record.timestamp and (record.timestamp.hour >= 22 or record.timestamp.hour < 5))
                else 0,
        })

    return pd.DataFrame(rows)