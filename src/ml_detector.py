from sklearn.ensemble import IsolationForest
import pandas as pd
from config import ISOLATION_FOREST_CONTAMINATION

def train_isolation_forest(
        df: pd.DataFrame
) -> IsolationForest:

    model = IsolationForest(
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=42
    )

    model.fit(df)

    return model

def predict_anomalies(
        model,
        df
):

    predictions = model.predict(df)

    return predictions