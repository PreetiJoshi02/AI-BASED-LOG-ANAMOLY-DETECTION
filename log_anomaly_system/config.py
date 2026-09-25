import os

# =====================================================================
# Central Project Configuration
# =====================================================================

# MongoDB Settings
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "LogAnomalyDB"
COLLECTION_NAME = "system_logs"
ALERTS_COLLECTION = "system_alerts"

# Windows Event Log Collector Settings
LOG_TYPES = ["System", "Application", "Security"]
COLLECT_LIMIT_PER_TYPE = 500  # Number of logs to fetch per channel in batch run
LIVE_POLL_INTERVAL = 5        # Polling interval in seconds for live monitor
MAX_STORED_LOGS = 2000        # Retention limit in MongoDB to maintain memory & performance

# Machine Learning & Feature Engineering
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "feature_encoders.pkl")
CONTAMINATION = 0.08  # Expected proportion of outliers/anomalies (8%)

FEATURE_COLUMNS = [
    "event_id",
    "source_encoded",
    "category",
    "log_type_encoded",
    "hour",
    "day",
    "month",
    "dayofweek"
]

# Web Dashboard Settings
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = True
DASHBOARD_LOG_LIMIT = 500  # Max logs displayed in dashboard table

# Default Email Alert Settings
DEFAULT_SMTP_SERVER = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587
