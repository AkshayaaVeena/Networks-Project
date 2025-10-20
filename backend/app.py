import os
import threading
from flask import Flask, request, jsonify
from capture import capture_packets
from analyze import analyze_pcap
from config import NOTIFICATION_LOG
import json
from pathlib import Path

app = Flask(__name__)

capture_done_event = threading.Event()
latest_analysis_result = {}

def capture_and_analyze_thread():
    capture_packets()
    analysis = analyze_pcap()
    global latest_analysis_result
    latest_analysis_result = analysis
    print("[+] Analysis result:", json.dumps(analysis, indent=2))
    capture_done_event.set()

@app.route("/upload", methods=["POST"])
def upload_notification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON received"}), 400

    with open(NOTIFICATION_LOG, "a") as f:
        f.write(json.dumps(data) + "\n")
    print("[+] Notification log received and saved.")

    thread = threading.Thread(target=capture_and_analyze_thread, daemon=True)
    thread.start()

    return jsonify({"status": "received"}), 200

@app.route("/latest", methods=["GET"])
def latest_analysis():
    if capture_done_event.is_set():
        return jsonify(latest_analysis_result)
    else:
        return jsonify({"status": "analysis in progress"}), 202

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
