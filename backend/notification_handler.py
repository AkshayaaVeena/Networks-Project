from pathlib import Path
import json
from datetime import datetime

# Store notifications inside backend/captures/notifications.log
LOG_FILE = Path(__file__).parent / "captures" / "notifications.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def handle_notification(data: dict):
    """
    Process a single notification sent from Android.
    Saves to log file and prints for debugging.
    """
    app_name = data.get("app", "unknown")
    title = data.get("title", "")
    text = data.get("text", "")
    timestamp = data.get("timestamp", datetime.now().isoformat())

    log_entry = {
        "app": app_name,
        "title": title,
        "text": text,
        "timestamp": timestamp
    }

    # Print to console
    print("📩 Notification received:", log_entry)

    # Append to log file
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")
