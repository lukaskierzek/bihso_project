import pandas as pd
from sklearn.ensemble import IsolationForest

from config import ISOLATION_FOREST_CONTAMINATION, RANDOM_STATE


def train_isolation_forest(
        df: pd.DataFrame
) -> IsolationForest:
    model = IsolationForest(
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=RANDOM_STATE
    )

    model.fit(df)

    return model


def predict_anomalies(
        model: IsolationForest,
        df: pd.DataFrame
):
    predictions = model.predict(df)

    return predictions
