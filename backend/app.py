from flask import Flask, request, jsonify
import threading
from capture import capture_packets
from analyze import analyze_pcap
from config import NOTIFICATION_LOG
from pathlib import Path
import json

app = Flask(__name__)

def capture_and_analyze_thread():
    capture_packets()
    analysis = analyze_pcap()
    print("[+] Analysis result:", json.dumps(analysis, indent=2))

@app.route("/upload", methods=["POST"])
def upload_notification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON received"}), 400

    # Append to notifications.log
    with open(NOTIFICATION_LOG, "a") as f:
        f.write(json.dumps(data) + "\n")
    print("[+] Notification log received and saved.")

    # Start capture and analysis in a **daemon thread**
    thread = threading.Thread(target=capture_and_analyze_thread, daemon=True)
    thread.start()

    return jsonify({"status": "received"}), 200

@app.route("/latest", methods=["GET"])
def latest_analysis():
    try:
        analysis = analyze_pcap()
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
