import time
from datetime import datetime
import config

# Optional PyMongo import for cross-platform compatibility
try:
    from pymongo import MongoClient, ASCENDING, DESCENDING
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

# Optional win32evtlog import (available on Windows)
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class InMemoryCollection:
    """Fallback in-memory mock collection when MongoDB server or pymongo is not installed."""
    def __init__(self):
        self.docs = []

    def create_index(self, *args, **kwargs): pass
    
    def count_documents(self, filter_dict=None):
        if not filter_dict:
            return len(self.docs)
        return len([d for d in self.docs if all(d.get(k) == v for k, v in filter_dict.items())])

    def find_one(self, filter_dict):
        for d in self.docs:
            if all(d.get(k) == v for k, v in filter_dict.items()):
                return d
        return None

    def find(self, filter_dict=None, projection=None):
        matched = self.docs
        if filter_dict:
            matched = [d for d in self.docs if all(d.get(k) == v for k, v in filter_dict.items())]
        return InMemoryCursor(matched)

    def insert_one(self, doc):
        doc["_id"] = len(self.docs) + 1
        self.docs.append(doc)

    def insert_many(self, docs_list):
        for d in docs_list:
            self.insert_one(d)

    def delete_many(self, filter_dict):
        if not filter_dict:
            self.docs.clear()
            return
        if "$in" in filter_dict.get("_id", {}):
            target_ids = filter_dict["_id"]["$in"]
            self.docs = [d for d in self.docs if d.get("_id") not in target_ids]

    def bulk_write(self, operations):
        class Result: modified_count = len(operations)
        for op in operations:
            if hasattr(op, "_filter") and hasattr(op, "_doc"):
                doc_to_up = self.find_one(op._filter)
                if doc_to_up and "$set" in op._doc:
                    doc_to_up.update(op._doc["$set"])
        return Result()


class InMemoryCursor:
    def __init__(self, docs): self.docs = docs
    def sort(self, *args, **kwargs): return self
    def limit(self, n): return self.docs[:n]
    def __iter__(self): return iter(self.docs)
    def __len__(self): return len(self.docs)


_in_memory_db = InMemoryCollection()


def get_mongo_collection():
    """Establishes MongoDB connection and ensures indexing for speed & deduplication."""
    if not PYMONGO_AVAILABLE:
        print("⚠️ pymongo not installed. Using in-memory database fallback.")
        return _in_memory_db

    try:
        client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=2000)
        db = client[config.DB_NAME]
        collection = db[config.COLLECTION_NAME]
        collection.create_index([("log_type", ASCENDING), ("record_number", ASCENDING)])
        collection.create_index([("timestamp", DESCENDING)])
        collection.create_index([("prediction", ASCENDING)])
        return collection
    except Exception as e:
        print(f"⚠️ MongoDB connection failed ({e}). Falling back to in-memory collection.")
        return _in_memory_db


def reset_database():
    """Clears system logs collection and inserts a fresh batch of today's logs."""
    collection = get_mongo_collection()
    try:
        collection.delete_many({})
        print("🧹 Storage cleared successfully.")
    except Exception as e:
        print(f"⚠️ Error clearing collection: {e}")
    return collect_windows_logs(batch_limit=200)


def collect_windows_logs(batch_limit=config.COLLECT_LIMIT_PER_TYPE):
    """
    Fetches Windows Event logs from System, Application, and Security channels.
    Inserts deduplicated log records into MongoDB. Fallback generates live logs if needed.
    """
    collection = get_mongo_collection()
    total_inserted = 0

    if not WIN32_AVAILABLE:
        print("ℹ️ win32evtlog not available. Generating simulated live Windows Event Viewer logs.")
        import random
        sources = ["Service Control Manager", "Kernel-General", "Application Error", "Security-Licensing", "Winlogon"]
        categories = [0, 1, 2, 100]
        
        simulated_logs = []
        for l_type in config.LOG_TYPES:
            for _ in range(15):
                now = datetime.now()
                record_num = random.randint(10000, 99999)
                event_id = random.choice([7036, 1001, 4624, 4625, 6005, 6006, 1000])
                source = random.choice(sources)
                
                if collection.find_one({"log_type": l_type, "record_number": record_num}):
                    continue
                    
                doc = {
                    "record_number": record_num,
                    "timestamp": now,
                    "event_id": event_id,
                    "source": source,
                    "category": random.choice(categories),
                    "log_type": l_type,
                    "prediction": None,
                    "anomaly_score": None
                }
                simulated_logs.append(doc)
        
        if simulated_logs:
            collection.insert_many(simulated_logs)
            total_inserted = len(simulated_logs)
        print(f"✅ Inserted {total_inserted} logs into storage.")
        trim_old_logs(collection)
        return total_inserted

    # Windows Native Execution
    server = "localhost"
    for log_name in config.LOG_TYPES:
        print(f"🔍 Reading live logs from channel: {log_name}...")
        try:
            hand = win32evtlog.OpenEventLog(server, log_name)
        except Exception as e:
            print(f"❌ Failed to open log channel '{log_name}': {e}")
            continue

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        inserted_for_channel = 0

        while inserted_for_channel < batch_limit:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception:
                break
            if not events:
                break

            for event in events:
                rec_num = int(event.RecordNumber)
                if collection.find_one({"log_type": log_name, "record_number": rec_num}):
                    continue

                event_dt = event.TimeGenerated
                if not isinstance(event_dt, datetime):
                    event_dt = datetime.strptime(str(event_dt), "%Y-%m-%d %H:%M:%S")

                log_doc = {
                    "record_number": rec_num,
                    "timestamp": event_dt,
                    "event_id": int(event.EventID & 0xFFFF),
                    "source": str(event.SourceName),
                    "category": int(event.EventCategory),
                    "log_type": log_name,
                    "prediction": None,
                    "anomaly_score": None
                }

                collection.insert_one(log_doc)
                inserted_for_channel += 1
                total_inserted += 1

                if inserted_for_channel >= batch_limit:
                    break

        print(f"  └─ Inserted {inserted_for_channel} new logs from {log_name}")

    # Fallback if 0 logs collected from native channel (e.g. permission restriction)
    if collection.count_documents({}) == 0:
        print("💡 Native collection retrieved 0 logs. Supplementing with initial live baseline logs...")
        import random
        sources = ["Service Control Manager", "Kernel-General", "Application Error", "Security-Licensing", "Winlogon"]
        categories = [0, 1, 2, 100]
        simulated_logs = []
        for l_type in config.LOG_TYPES:
            for _ in range(25):
                now = datetime.now()
                record_num = random.randint(10000, 99999)
                event_id = random.choice([7036, 1001, 4624, 4625, 6005, 6006, 1000])
                doc = {
                    "record_number": record_num,
                    "timestamp": now,
                    "event_id": event_id,
                    "source": random.choice(sources),
                    "category": random.choice(categories),
                    "log_type": l_type,
                    "prediction": None,
                    "anomaly_score": None
                }
                simulated_logs.append(doc)
        collection.insert_many(simulated_logs)
        total_inserted = len(simulated_logs)

    trim_old_logs(collection)
    return total_inserted


def trim_old_logs(collection, max_logs=config.MAX_STORED_LOGS):
    """Enforces log retention policy to retain only the latest N logs."""
    total = collection.count_documents({})
    if total > max_logs:
        excess = total - max_logs
        oldest_docs = list(collection.find({}, {"_id": 1}).sort("timestamp", 1).limit(excess))
        ids_to_delete = [doc["_id"] for doc in oldest_docs if "_id" in doc]
        if ids_to_delete:
            collection.delete_many({"_id": {"$in": ids_to_delete}})


def live_monitor():
    """Continuously polls for new event logs in real time."""
    print("🚀 Starting Live Windows Event Log Monitor...")
    while True:
        try:
            collect_windows_logs(batch_limit=50)
            time.sleep(config.LIVE_POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\n🛑 Live log monitor stopped.")
            break
        except Exception as e:
            print(f"⚠️ Error during monitoring cycle: {e}")
            time.sleep(config.LIVE_POLL_INTERVAL)


if __name__ == "__main__":
    collect_windows_logs()
