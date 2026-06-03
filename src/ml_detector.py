from sklearn.ensemble import IsolationForest


def train_isolation_forest(df):

    model = IsolationForest(
        contamination=0.05,
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