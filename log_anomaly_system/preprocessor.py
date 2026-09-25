import os
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import config


class EncoderManager:
    """Manages persistent LabelEncoders for categorical log features."""

    def __init__(self):
        self.source_encoder = LabelEncoder()
        self.log_type_encoder = LabelEncoder()
        self.is_fitted = False

    def fit_transform(self, df):
        df_copy = df.copy()

        # Fill NaNs
        df_copy["source"] = df_copy["source"].fillna("Unknown").astype(str)
        df_copy["log_type"] = df_copy["log_type"].fillna("Unknown").astype(str)

        # Fit & Transform Categorical Columns
        df_copy["source_encoded"] = self.source_encoder.fit_transform(df_copy["source"])
        df_copy["log_type_encoded"] = self.log_type_encoder.fit_transform(df_copy["log_type"])
        self.is_fitted = True

        return df_copy

    def transform(self, df):
        df_copy = df.copy()
        df_copy["source"] = df_copy["source"].fillna("Unknown").astype(str)
        df_copy["log_type"] = df_copy["log_type"].fillna("Unknown").astype(str)

        # Handle unseen labels gracefully during live inference
        df_copy["source_encoded"] = df_copy["source"].apply(
            lambda x: self.source_encoder.transform([x])[0]
            if x in self.source_encoder.classes_
            else -1
        )

        df_copy["log_type_encoded"] = df_copy["log_type"].apply(
            lambda x: self.log_type_encoder.transform([x])[0]
            if x in self.log_type_encoder.classes_
            else -1
        )

        return df_copy

    def save(self, filepath=config.ENCODER_PATH):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"💾 Feature Encoders saved to {filepath}")

    @staticmethod
    def load(filepath=config.ENCODER_PATH):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Encoder file missing at {filepath}")
        mgr = joblib.load(filepath)
        print(f"📂 Feature Encoders loaded successfully from {filepath}")
        return mgr


def extract_temporal_features(df):
    """Extracts hour, day, month, and dayofweek from event timestamps."""
    df_copy = df.copy()
    if "timestamp" in df_copy:
        df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"])
        df_copy["hour"] = df_copy["timestamp"].dt.hour
        df_copy["day"] = df_copy["timestamp"].dt.day
        df_copy["month"] = df_copy["timestamp"].dt.month
        df_copy["dayofweek"] = df_copy["timestamp"].dt.dayofweek
    else:
        df_copy["hour"] = 12
        df_copy["day"] = 1
        df_copy["month"] = 1
        df_copy["dayofweek"] = 0
    return df_copy


def prepare_training_data(raw_docs):
    """Transforms raw document list from MongoDB into ML feature matrix X."""
    if not raw_docs:
        return pd.DataFrame(), pd.DataFrame(), None

    df = pd.DataFrame(raw_docs)
    df = extract_temporal_features(df)

    encoder_mgr = EncoderManager()
    df = encoder_mgr.fit_transform(df)

    for col in config.FEATURE_COLUMNS:
        if col not in df:
            df[col] = 0

    X = df[config.FEATURE_COLUMNS]
    return df, X, encoder_mgr


def prepare_inference_data(raw_docs, encoder_mgr):
    """Transforms unanalyzed log documents using pre-fitted encoders."""
    if not raw_docs:
        return pd.DataFrame(), pd.DataFrame()

    df = pd.DataFrame(raw_docs)
    df = extract_temporal_features(df)
    df = encoder_mgr.transform(df)

    for col in config.FEATURE_COLUMNS:
        if col not in df:
            df[col] = 0

    X = df[config.FEATURE_COLUMNS]
    return df, X
