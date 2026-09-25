import argparse
import threading
import time
import config
from collector import collect_windows_logs, live_monitor, reset_database
from trainer import train_model
from detector import AnomalyDetectorEngine, detect_anomalies
from app import app


def run_background_pipeline():
    """Runs continuous log collection and AI anomaly detection in a background thread."""
    print("🔄 Background Live Pipeline Thread Started.")
    engine = AnomalyDetectorEngine()
    while True:
        try:
            # 1. Collect live Windows logs
            collect_windows_logs(batch_limit=50)
            # 2. Score unanalyzed logs with ML model
            engine.process_unscored_logs()
            time.sleep(config.LIVE_POLL_INTERVAL)
        except Exception as e:
            print(f"⚠️ Error in background pipeline: {e}")
            time.sleep(config.LIVE_POLL_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="AI-Based Windows Log Anomaly Detection System")
    parser.add_argument("--train", action="store_true", help="Train Isolation Forest ML Model")
    parser.add_argument("--collect", action="store_true", help="Run single pass log collection")
    parser.add_argument("--detect", action="store_true", help="Run single pass anomaly detection")
    parser.add_argument("--monitor", action="store_true", help="Run live background log monitor")
    parser.add_argument("--reset", action="store_true", help="Clear storage and reload fresh logs")
    parser.add_argument("--all", action="store_true", help="Run full system (Background pipeline + Flask Dashboard)")

    args = parser.parse_args()

    if args.train:
        train_model()
    elif args.collect:
        collect_windows_logs()
    elif args.detect:
        detect_anomalies()
    elif args.monitor:
        live_monitor()
    elif args.reset:
        reset_database()
    elif args.all:
        print("🚀 Starting Complete AI Log Anomaly Detection System...")
        # Start background monitor thread
        bg_thread = threading.Thread(target=run_background_pipeline, daemon=True)
        bg_thread.start()
        # Launch Flask Web App
        app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)
    else:
        # Default action: launch Flask Web Application
        print("=========================================================================")
        print("🛡️ AI-BASED WINDOWS LOG ANOMALY DETECTION SYSTEM")
        print("=========================================================================")
        print(f"🌐 Launching Web Dashboard at: http://localhost:{config.FLASK_PORT}")
        print("💡 Tip: Run 'python main.py --all' to enable real-time background log polling.")
        print("=========================================================================")
        app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)


if __name__ == "__main__":
    main()
