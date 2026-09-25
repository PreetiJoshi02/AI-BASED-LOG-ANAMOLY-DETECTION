from flask import Flask, render_template, jsonify, request
import pandas as pd
from datetime import datetime
import config
from collector import get_mongo_collection, collect_windows_logs, reset_database
from detector import AnomalyDetectorEngine
from alerts import update_alert_config, get_alert_config, send_desktop_notification, send_email_alert, dispatch_anomaly_alert

app = Flask(__name__)
app.config['SECRET_KEY'] = 'log-anomaly-detection-secret'

# Initialize detector engine instance for on-demand scoring
detector_engine = AnomalyDetectorEngine()


def get_db_data():
    """Fetches latest logs from storage, ensures scoring, and returns DataFrame."""
    try:
        collection = get_mongo_collection()

        # Auto-collect if empty
        if collection.count_documents({}) == 0:
            print("💡 Storage empty. Triggering initial log collection...")
            collect_windows_logs(batch_limit=300)

        # Ensure unscored logs are scored by ML model
        detector_engine.process_unscored_logs()

        # Fetch latest logs
        logs_list = list(collection.find())
        if not logs_list:
            return pd.DataFrame(), []

        # Sort descending by timestamp
        logs_list.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        logs_list = logs_list[:config.DASHBOARD_LOG_LIMIT]

        df = pd.DataFrame(logs_list)

        # Convert timestamps safely
        if "timestamp" in df:
            df["timestamp"] = pd.to_datetime(df["timestamp"])

        return df, logs_list

    except Exception as e:
        print(f"❌ Database error in Flask app: {e}")
        return pd.DataFrame(), []


@app.route("/")
def dashboard():
    """Main Web Dashboard Route."""
    df, logs_raw = get_db_data()
    alert_cfg = get_alert_config()

    if df.empty:
        return render_template(
            "index.html",
            total_logs=0, normal=0, anomalies=0, anomaly_rate=0,
            logs=[],
            event_labels=[], event_values=[],
            hour_labels=[f"{h}:00" for h in range(24)], hour_values=[0]*24,
            source_labels=[], source_values=[],
            logtype_labels=[], logtype_values=[],
            alert_cfg=alert_cfg
        )

    # 1. Dashboard Card KPI Metrics
    total_logs = len(df)
    anomalies = int((df["prediction"] == -1).sum()) if "prediction" in df else 0
    normal = int((df["prediction"] == 1).sum()) if "prediction" in df else total_logs
    anomaly_rate = round((anomalies / total_logs) * 100 if total_logs else 0, 2)

    # 2. Chart Data Aggregations
    # Top 10 Event IDs
    event_counts = df["event_id"].value_counts().head(10) if "event_id" in df else pd.Series()
    event_labels = event_counts.index.astype(str).tolist()
    event_values = [int(v) for v in event_counts.values.tolist()]

    # Logs by Hour (0:00 - 23:00)
    if "timestamp" in df:
        df["hour"] = df["timestamp"].dt.hour
        hour_counts = df.groupby("hour").size().reindex(range(24), fill_value=0)
        hour_values = [int(v) for v in hour_counts.tolist()]
    else:
        hour_values = [0] * 24
    hour_labels = [f"{h}:00" for h in range(24)]

    # Top 10 Log Sources (Truncated for clean rendering on Chart 4)
    source_counts = df["source"].value_counts().head(10) if "source" in df else pd.Series()
    source_labels = [str(s)[:22] + "..." if len(str(s)) > 25 else str(s) for s in source_counts.index.tolist()]
    source_values = [int(v) for v in source_counts.values.tolist()]

    # Log Types
    logtype_counts = df["log_type"].value_counts() if "log_type" in df else pd.Series()
    logtype_labels = logtype_counts.index.tolist()
    logtype_values = [int(v) for v in logtype_counts.values.tolist()]

    # Format log list for tabular rendering
    logs_table = []
    for log in logs_raw:
        ts = log.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
        
        logs_table.append({
            "record_number": log.get("record_number", "-"),
            "timestamp": ts_str,
            "log_type": log.get("log_type", "Unknown"),
            "event_id": log.get("event_id", 0),
            "source": log.get("source", "Unknown"),
            "category": log.get("category", 0),
            "prediction": log.get("prediction", 1),
            "anomaly_score": log.get("anomaly_score", 0.0)
        })

    return render_template(
        "index.html",
        total_logs=total_logs,
        normal=normal,
        anomalies=anomalies,
        anomaly_rate=anomaly_rate,
        logs=logs_table,
        event_labels=event_labels,
        event_values=event_values,
        hour_labels=hour_labels,
        hour_values=hour_values,
        source_labels=source_labels,
        source_values=source_values,
        logtype_labels=logtype_labels,
        logtype_values=logtype_values,
        alert_cfg=alert_cfg
    )


@app.route("/api/metrics")
def api_metrics():
    """JSON Endpoint for Live AJAX Polling."""
    df, logs_raw = get_db_data()
    if df.empty:
        return jsonify({"status": "no_data"})

    total_logs = len(df)
    anomalies = int((df["prediction"] == -1).sum()) if "prediction" in df else 0
    normal = total_logs - anomalies
    anomaly_rate = round((anomalies / total_logs) * 100 if total_logs else 0, 2)

    return jsonify({
        "status": "success",
        "total_logs": total_logs,
        "normal": normal,
        "anomalies": anomalies,
        "anomaly_rate": anomaly_rate
    })


@app.route("/api/subscribe_email", methods=["POST"])
def subscribe_email():
    """Subscribes email and triggers instant confirmation alert."""
    data = request.json or {}
    email = data.get("email", "").strip()
    sender_email = data.get("sender_email", "").strip()
    sender_password = data.get("sender_password", "").strip()

    if not email:
        return jsonify({"status": "error", "message": "Email address is required."}), 400

    update_alert_config(email=email, sender_email=sender_email, sender_password=sender_password)

    # Trigger welcome desktop toast
    send_desktop_notification("Alert Subscription Active 🔔", f"Notifications enabled for {email}")

    # Trigger welcome confirmation email if SMTP password provided
    welcome_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #ffffff; padding: 20px;">
        <div style="max-width: 500px; margin: 0 auto; background-color: #111827; border: 1px solid #6366f1; border-radius: 12px; padding: 24px;">
          <h2 style="color: #6366f1;">✅ Alert System Subscribed</h2>
          <p>You have successfully registered <b>{email}</b> to receive real-time Windows Log Anomaly Detection security alerts.</p>
          <p style="color: #9ca3af; font-size: 13px;">Whenever an anomalous Windows event is flagged by the Isolation Forest model, an alert report will be sent here.</p>
        </div>
      </body>
    </html>
    """
    email_ok, email_msg = send_email_alert("Welcome to AI Log Anomaly System Alerts", welcome_html, recipient=email)

    return jsonify({
        "status": "success",
        "message": f"Successfully registered {email}!",
        "email_sent": email_ok,
        "email_status": email_msg
    })


@app.route("/api/test_alert", methods=["POST"])
def test_alert():
    """Triggers an immediate test alert to verify desktop toasts & emails."""
    sample_log = {
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "log_type": "Security",
        "anomaly_score": -0.2145,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    result = dispatch_anomaly_alert(sample_log)
    return jsonify({
        "status": "success",
        "message": "Test anomaly alert dispatched!",
        "result": result
    })


@app.route("/api/trigger_collect", methods=["POST"])
def trigger_collect():
    """Manual trigger to fetch fresh Windows logs and score them immediately."""
    new_count = collect_windows_logs(batch_limit=100)
    scored_count = detector_engine.process_unscored_logs()
    return jsonify({
        "status": "success",
        "new_logs_collected": new_count,
        "logs_scored": scored_count
    })


@app.route("/api/reset_logs", methods=["POST"])
def reset_logs():
    """Purges storage and fetches a fresh set of today's Windows logs."""
    count = reset_database()
    scored = detector_engine.process_unscored_logs()
    return jsonify({
        "status": "success",
        "logs_reset": count,
        "logs_scored": scored
    })


if __name__ == "__main__":
    print(f"🚀 Launching Log Anomaly Detection Flask App on http://localhost:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
