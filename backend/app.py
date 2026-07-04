from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import json
import uuid

from capture import capture_packets
from analyze import analyze_pcap
from config import NOTIFICATION_LOG, FLASK_DEBUG, FLASK_PORT
from db import save_analysis, get_latest_analysis

app = Flask(__name__)
CORS(app)





_lock = threading.Lock()
_jobs = {}
_latest_job_id = None


def capture_and_analyze_thread(job_id):
    try:
        capture_packets()
        analysis = analyze_pcap()
        with _lock:
            _jobs[job_id] = {"status": "done", "result": analysis, "error": None}
        save_analysis(job_id, analysis)
        print(f"[+] Analysis complete for job {job_id}:", json.dumps(analysis, indent=2))
    except Exception as e:
        with _lock:
            _jobs[job_id] = {"status": "error", "result": None, "error": str(e)}
        print(f"[!] Capture/analysis failed for job {job_id}: {e}")


@app.route("/upload", methods=["POST"])
def upload_notification():
    global _latest_job_id
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON received"}), 400

    with open(NOTIFICATION_LOG, "a") as f:
        f.write(json.dumps(data) + "\n")
    print("[+] Notification log received and saved.")

    job_id = str(uuid.uuid4())
    with _lock:
        _jobs[job_id] = {"status": "running", "result": None, "error": None}



        _latest_job_id = job_id

    thread = threading.Thread(target=capture_and_analyze_thread, args=(job_id,), daemon=True)
    thread.start()

    return jsonify({"status": "received", "job_id": job_id}), 200


@app.route("/latest", methods=["GET"])
def latest_analysis():
    """Returns the most recent analysis, or a specific one via ?job_id=...

    Falls back to MongoDB if nothing is in memory yet (e.g. right after a
    server restart), so /latest still works as long as Mongo has history.
    """
    job_id = request.args.get("job_id")

    with _lock:
        job = _jobs.get(job_id) if job_id else (_jobs.get(_latest_job_id) if _latest_job_id else None)

    if job:
        if job["status"] == "done":
            return jsonify(job["result"])
        if job["status"] == "error":
            return jsonify({"status": "error", "error": job["error"]}), 500
        return jsonify({"status": "analysis in progress"}), 202

    persisted = get_latest_analysis()
    if persisted:
        return jsonify(persisted)

    return jsonify({"status": "no analysis available yet"}), 404


@app.route("/jobs/<job_id>/status", methods=["GET"])
def job_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job_id"}), 404
    return jsonify({"job_id": job_id, "status": job["status"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=FLASK_DEBUG)
