import os
import time
import joblib
import config
from collector import get_mongo_collection
from preprocessor import EncoderManager, prepare_inference_data
from trainer import train_model
from alerts import dispatch_anomaly_alert


class UpdateOp:
    """Fallback mock update operation when PyMongo is not installed."""
    def __init__(self, filter_dict, doc_dict):
        self._filter = filter_dict
        self._doc = doc_dict


class AnomalyDetectorEngine:
    """Live Anomaly Detection Engine running inference on incoming Windows Event logs."""

    def __init__(self):
        self.model = None
        self.encoder_mgr = None
        self.load_or_train_model()

    def load_or_train_model(self):
        """Loads trained Isolation Forest and Encoders, or triggers training if missing."""
        if not os.path.exists(config.MODEL_PATH) or not os.path.exists(config.ENCODER_PATH):
            print("⚠️ Trained model or encoder artifacts missing. Triggering automated training...")
            train_model()

        self.model = joblib.load(config.MODEL_PATH)
        self.encoder_mgr = EncoderManager.load(config.ENCODER_PATH)
        print("⚡ Anomaly Detector Engine Initialized Successfully!")

    def process_unscored_logs(self, force_all=False):
        """
        Fetches unprocessed logs, computes predictions & anomaly scores,
        updates the database directly, and dispatches real-time alerts.
        """
        try:
            collection = get_mongo_collection()
        except Exception as e:
            print(f"❌ Failed to connect to storage: {e}")
            return 0

        # Query filter
        query = {} if force_all else {"prediction": None}
        unscored_docs = list(collection.find(query))

        if not unscored_docs:
            return 0

        print(f"🔍 Analyzing {len(unscored_docs)} logs for live anomalies...")

        # Prepare inference feature matrix
        df, X = prepare_inference_data(unscored_docs, self.encoder_mgr)

        if X.empty:
            return 0

        # Run Isolation Forest prediction
        preds = self.model.predict(X)
        scores = self.model.decision_function(X)

        bulk_operations = []
        anomaly_count = 0

        for i, doc in enumerate(unscored_docs):
            pred_val = int(preds[i])           # -1 = Anomaly, 1 = Normal
            score_val = float(scores[i])       # Lower score = higher anomaly probability

            if pred_val == -1:
                anomaly_count += 1
                # Trigger live desktop and email alert
                try:
                    dispatch_anomaly_alert(doc)
                except Exception as alert_err:
                    print(f"⚠️ Error dispatching alert for log: {alert_err}")

            # Try using PyMongo UpdateOne if available
            try:
                from pymongo import UpdateOne
                op = UpdateOne(
                    {"_id": doc["_id"]},
                    {"$set": {"prediction": pred_val, "anomaly_score": round(score_val, 4)}}
                )
            except ImportError:
                op = UpdateOp(
                    {"_id": doc["_id"]},
                    {"$set": {"prediction": pred_val, "anomaly_score": round(score_val, 4)}}
                )

            bulk_operations.append(op)

        if bulk_operations:
            result = collection.bulk_write(bulk_operations)
            modified = getattr(result, "modified_count", len(bulk_operations))
            print(f"✅ Processed {modified} logs -> Flagged {anomaly_count} ANOMALIES 🚨")

        return len(bulk_operations)

    def run_live_loop(self, poll_interval=config.LIVE_POLL_INTERVAL):
        """Continuous background loop scanning and scoring live incoming logs."""
        print("🚀 Anomaly Detection Engine background service started...")
        while True:
            try:
                self.process_unscored_logs()
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                print("\n🛑 Anomaly Detection Engine stopped.")
                break
            except Exception as e:
                print(f"⚠️ Error in detection loop: {e}")
                time.sleep(poll_interval)


def detect_anomalies():
    """Helper function to run single pass anomaly scoring."""
    engine = AnomalyDetectorEngine()
    return engine.process_unscored_logs(force_all=True)


if __name__ == "__main__":
    detect_anomalies()
