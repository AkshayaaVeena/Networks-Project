# Update Channel Security Monitor

## Overview
Monitors and evaluates the security of app update/push-notification channels by
capturing live network traffic, parsing TLS handshakes, and scoring each
connection on cipher strength, forward secrecy, certificate trust, and
TCP-level health (packet loss, handshake delay).

## Features
- Live packet capture via `tshark`/`pyshark`
- TLS version, cipher suite, certificate, and SNI/domain analysis
- Custom weighted security scoring per app (0-100)
- TCP-level packet loss and handshake delay estimation per flow
- Results persisted to MongoDB (falls back to memory-only mode if MongoDB
  isn't reachable, so the API keeps working either way)
- REST API consumed by the React dashboard for live charts

## Installation
```bash
cd backend
pip install -r requirements.txt
```

`tshark` (from Wireshark) must also be installed and on your PATH, since
`pyshark` shells out to it for packet capture.

## Configuration
All settings are environment variables (optionally via a `.env` file in
`backend/`) - nothing below needs to be hardcoded or edited in source:

| Variable | Default | Description |
|---|---|---|
| `CAPTURE_INTERFACE` | `Ethernet 4` | Network interface to sniff on (e.g. `en0`, `eth0`, `Wi-Fi`) |
| `CAPTURE_DURATION_SECONDS` | `20` | How long each capture runs |
| `PCAP_OUTPUT` | `captures/notifications.pcap` | Where the capture file is written |
| `NOTIFICATION_LOG` | `notifications.log` | Where incoming notification payloads are appended |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB_NAME` | `security_monitor` | Database name |
| `MONGO_COLLECTION` | `analysis_results` | Collection name |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `FLASK_PORT` | `3000` | Port the API listens on |

## Running
```bash
python app.py
```

## API
- `POST /upload` - submit a notification payload; kicks off a background
  capture + analysis job. Returns `{"status": "received", "job_id": "..."}`.
- `GET /latest` - latest completed analysis (optionally `?job_id=...` for a
  specific job). Falls back to the most recent MongoDB record if nothing is
  in memory (e.g. after a restart).
- `GET /jobs/<job_id>/status` - check a specific job's status (`running`,
  `done`, or `error`).

## Tests
```bash
pytest tests/
```
Covers the scoring/analysis logic (`score_cipher`, `check_forward_secrecy`,
`check_certificate`, `is_suspicious_domain`, `calculate_app_score`) with pure
unit tests - no live capture or MongoDB needed to run them.
