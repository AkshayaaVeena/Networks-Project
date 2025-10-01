import time
import json
from pathlib import Path
from flask import Flask, jsonify
from capture import capture_notifications
from analyze import analyze_capture

# Initialize Flask app
app = Flask(__name__)

# Path to notification log (from your Android listener)
LOG_FILE = Path("notifications.log")  

def get_last_notification():
    """Reads the last notification from log file."""
    if LOG_FILE.exists():
        with LOG_FILE.open("r") as f:
            lines = f.readlines()
            if lines:
                return json.loads(lines[-1].strip())
    return {"app": "Unknown App", "title": "", "text": ""}

def capture_and_analyze():
    """Captures packets, analyzes PCAP, and adds last notification info."""
    # Step 1: Capture packets (returns pcap file path)
    pcap_file = capture_notifications()

    # Step 2: Analyze captured PCAP
    result = analyze_capture(pcap_file)

    # Step 3: Add last notification info
    last_notification = get_last_notification()
    result["app"] = last_notification.get("app", "Unknown App")
    result["title"] = last_notification.get("title", "")
    result["text"] = last_notification.get("text", "")

    return result

# Flask route to view latest analysis in browser/JSON
@app.route("/latest", methods=["GET"])
def latest_analysis():
    try:
        result = capture_and_analyze()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

# Optional: continuous console printing (like your old loop)
def main_loop():
    while True:
        try:
            result = capture_and_analyze()

            print("📊 Security Analysis Result:")
            for k, v in result.items():
                print(f"  {k}: {v}")

            print("⏳ Waiting 5 seconds before next capture...\n")
            time.sleep(5)

        except KeyboardInterrupt:
            print("🛑 Stopped by user")
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    # Run Flask API in a separate thread if needed
    # For simplicity, here we just run the API
    app.run(host="0.0.0.0", port=5000)
    # If you want console loop instead, comment above line and uncomment below:
    # main_loop()
