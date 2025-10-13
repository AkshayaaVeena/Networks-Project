import os
import threading
from flask import Flask, request, jsonify
from capture import capture_packets
from analyze import analyze_pcap
from config import NOTIFICATION_LOG
import json
from pathlib import Path

app = Flask(__name__)

# A threading event to signal when capture and analysis is complete
capture_done_event = threading.Event()

# Shared variable to store the analysis result
latest_analysis_result = {}

def capture_and_analyze_thread():
    capture_packets()
    # Analyze the pcap after capture
    analysis = analyze_pcap()
    global latest_analysis_result
    latest_analysis_result = analysis
    print("[+] Analysis result:", json.dumps(analysis, indent=2))
    # Signal that capture and analysis are complete
    capture_done_event.set()

@app.route("/upload", methods=["POST"])
def upload_notification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON received"}), 400

    # Append to notifications.log
    with open(NOTIFICATION_LOG, "a") as f:
        f.write(json.dumps(data) + "\n")
    print("[+] Notification log received and saved.")

    # Start capture and analysis in a daemon thread
    thread = threading.Thread(target=capture_and_analyze_thread, daemon=True)
    thread.start()

    return jsonify({"status": "received"}), 200

@app.route("/latest", methods=["GET"])
def latest_analysis():
    # Check if analysis is done or still running
    if capture_done_event.is_set():
        return jsonify(latest_analysis_result)
    else:
        return jsonify({"status": "analysis in progress"}), 202

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
