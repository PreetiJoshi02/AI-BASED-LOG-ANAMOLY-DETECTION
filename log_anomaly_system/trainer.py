import os
import random
import joblib
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import config
from collector import get_mongo_collection
from preprocessor import prepare_training_data


def generate_synthetic_logs(num_logs=1200):
    """Generates synthetic baseline Windows event logs for model training."""
    sources = ["Service Control Manager", "Kernel-General", "Application Error", "Security-Licensing", "Winlogon", "System"]
    normal_event_ids = [7036, 1001, 6005, 6006, 1000, 4624]
    anomaly_event_ids = [4625, 7040, 1102, 4720]  # Failed logins, audit log cleared, account created
    
    docs = []
    base_time = datetime.now() - timedelta(days=7)

    for i in range(num_logs):
        is_anomaly = random.random() < config.CONTAMINATION
        event_id = random.choice(anomaly_event_ids) if is_anomaly else random.choice(normal_event_ids)
        
        # Anomalies often occur during unusual hours (01:00 - 04:00 AM)
        if is_anomaly:
            rand_hour = random.choice([1, 2, 3, 4, 23])
        else:
            rand_hour = random.randint(8, 18)

        log_time = base_time + timedelta(days=random.randint(0, 6), hours=rand_hour, minutes=random.randint(0, 59))
        
        doc = {
            "record_number": 10000 + i,
            "timestamp": log_time,
            "event_id": event_id,
            "source": random.choice(sources),
            "category": random.choice([0, 1, 2, 100]),
            "log_type": random.choice(config.LOG_TYPES),
            "prediction": None,
            "anomaly_score": None
        }
        docs.append(doc)

    return docs


def train_model():
    """Trains Isolation Forest model on system logs or synthetic baseline."""
    print("=================================================================")
    print("🤖 STARTING AI LOG ANOMALY DETECTION MODEL TRAINING")
    print("=================================================================")

    collection = get_mongo_collection()
    raw_docs = list(collection.find())
    print(f"📥 Loaded {len(raw_docs)} logs from system database.")

    if len(raw_docs) < 100:
        print("💡 Database has < 100 logs. Supplementing with synthetic logs for training...")
        synthetic_docs = generate_synthetic_logs(1200)
        raw_docs.extend(synthetic_docs)

    df, X, encoder_mgr = prepare_training_data(raw_docs)

    if X.empty:
        print("❌ Training failed: Empty feature matrix.")
        return

    print(f"\n🌲 Fitting Isolation Forest model on {len(X)} samples with features:")
    print(f"   {list(X.columns)}\n")

    model = IsolationForest(
        n_estimators=100,
        contamination=config.CONTAMINATION,
        random_state=42,
        n_jobs=-1
    )
    
    preds = model.fit_predict(X)

    # Save trained artifacts
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    joblib.dump(model, config.MODEL_PATH)
    encoder_mgr.save(config.ENCODER_PATH)

    normal_count = int((preds == 1).sum())
    anomaly_count = int((preds == -1).sum())
    rate = round((anomaly_count / len(preds)) * 100, 2)

    print(f"📊 Training Set Performance Summary:")
    print(f"  ├─ Normal Logs Classified   : {normal_count}")
    print(f"  ├─ Anomalous Logs Classified : {anomaly_count}")
    print(f"  └─ Anomaly Rate             : {rate}%\n")
    print(f"💾 Model saved to: {config.MODEL_PATH}")
    print("\n✅ AI Model Training Complete!")
    print("================================================")


if __name__ == "__main__":
    train_model()
