"""Central configuration, overridable via environment variables (or a .env file)."""
from pathlib import Path
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


PCAP_OUTPUT = Path(os.getenv("PCAP_OUTPUT", "captures/notifications.pcap"))
NOTIFICATION_LOG = Path(os.getenv("NOTIFICATION_LOG", "notifications.log"))




CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "Wi-fi")
CAPTURE_DURATION_SECONDS = int(os.getenv("CAPTURE_DURATION_SECONDS", "20"))


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "security_monitor")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "analysis_results")


FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
FLASK_PORT = int(os.getenv("FLASK_PORT", "3000"))
