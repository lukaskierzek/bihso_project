import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import (
    ISOLATION_FOREST_CONTAMINATION,
    LOCAL_OUTLIER_FACTOR_CONTAMINATION,
    RANDOM_STATE,
)


def train_isolation_forest(
        df: pd.DataFrame
) -> Pipeline:
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("model", IsolationForest(
                n_estimators=200,
                contamination=ISOLATION_FOREST_CONTAMINATION,
                random_state=RANDOM_STATE
            )),
        ]
    )

    model.fit(df)

    return model


def predict_anomalies(
        model: Pipeline,
        df: pd.DataFrame
):
    predictions = model.predict(df)

    return predictions


def train_local_outlier_factor(
        df: pd.DataFrame
) -> Pipeline:
    neighbors = min(20, max(2, len(df) - 1))

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("model", LocalOutlierFactor(
                n_neighbors=neighbors,
                contamination=LOCAL_OUTLIER_FACTOR_CONTAMINATION,
                novelty=True
            )),
        ]
    )

    model.fit(df)

    return model


def predict_local_outlier_factor(
        model: Pipeline,
        df: pd.DataFrame
):
    return model.predict(df)
