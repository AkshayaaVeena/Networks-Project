"""MongoDB persistence for analysis results.

Falls back gracefully to memory-only mode if MongoDB isn't reachable, so a
missing/unreachable database never crashes the capture pipeline - it just
means results won't survive a server restart.
"""
from datetime import datetime, timezone

from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

from config import MONGO_URI, MONGO_DB_NAME, MONGO_COLLECTION

_client = None
_collection = None
_unavailable = False


def get_collection():
    """Lazily create and cache the MongoDB collection handle."""
    global _client, _collection, _unavailable

    if _collection is not None:
        return _collection
    if _unavailable:
        return None

    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        _client.admin.command("ping")
        _collection = _client[MONGO_DB_NAME][MONGO_COLLECTION]
        return _collection
    except PyMongoError as e:
        print(f"[!] MongoDB unavailable ({e}); continuing in memory-only mode.")
        _unavailable = True
        return None


def save_analysis(job_id: str, analysis: dict) -> bool:
    """Persist one analysis result. Returns True if it was actually saved."""
    collection = get_collection()
    if collection is None:
        return False

    doc = {**analysis, "job_id": job_id, "created_at": datetime.now(timezone.utc)}
    try:
        collection.insert_one(doc)
        return True
    except PyMongoError as e:
        print(f"[!] Failed to save analysis to MongoDB: {e}")
        return False


def get_latest_analysis():
    """Return the most recently saved analysis document, or None."""
    collection = get_collection()
    if collection is None:
        return None

    try:
        doc = collection.find_one(sort=[("created_at", DESCENDING)])
        if doc:
            doc.pop("_id", None)
        return doc
    except PyMongoError as e:
        print(f"[!] Failed to read latest analysis from MongoDB: {e}")
        return None
