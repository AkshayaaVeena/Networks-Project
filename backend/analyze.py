import asyncio
import pyshark
from config import PCAP_OUTPUT, NOTIFICATION_LOG
import json
from collections import defaultdict

TLS_VERSIONS = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3"
}

# Scoring for TLS versions
TLS_SCORING = {
    "TLS 1.0": 10,  # Older versions get lower scores
    "TLS 1.1": 15,
    "TLS 1.2": 30,
    "TLS 1.3": 40   # Newest versions get the highest score
}

# Scoring for ciphers (weak to strong)
CIPHER_SCORING = {
    "RC4": 5,
    "3DES": 10,
    "AES128": 20,
    "AES256": 30,
    "AES-GCM": 40
}

# Scoring based on delay (lower delay = higher score)
DELAY_SCORING = {
    (0, 50): 40,    # Excellent performance (0-50ms)
    (51, 100): 30,  # Good performance (51-100ms)
    (101, 200): 20, # Average performance (101-200ms)
    (201, float('inf')): 10  # Poor performance (>200ms)
}

# Scoring based on packet loss
def calculate_packet_loss_score(packet_loss_percent):
    if packet_loss_percent == 0:
        return 40  # No packet loss is best
    elif packet_loss_percent <= 10:
        return 30  # Small packet loss
    elif packet_loss_percent <= 30:
        return 20  # Moderate packet loss
    else:
        return 10  # High packet loss

def calculate_score(delay_ms, packet_loss_percent, tls_version, cipher):
    # Delay score
    for delay_range, score in DELAY_SCORING.items():
        if delay_range[0] <= delay_ms <= delay_range[1]:
            delay_score = score
            break
    
    # Packet loss score
    packet_loss_score = calculate_packet_loss_score(packet_loss_percent)
    
    # TLS version score
    tls_score = TLS_SCORING.get(tls_version, 0)
    
    # Cipher score
    cipher_score = CIPHER_SCORING.get(cipher, 0)
    
    # Combine all factors for a final score, weighted to your preference
    total_score = (delay_score * 0.4) + (packet_loss_score * 0.3) + (tls_score * 0.2) + (cipher_score * 0.1)
    
    return int(total_score)

def analyze_pcap():
    # Ensure an event loop exists in this thread
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError as e:
        if str(e).startswith('There is no current event loop in thread'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        else:
            raise  # Raise if there's an unexpected error

    result = {
        "summary_score": 0,
        "average_delay_ms": 0,
        "packet_loss_percent": 0,
        "apps": defaultdict(lambda: {"notifications": 0, "tls_sessions": [], "score": 0, "avg_delay_ms": 0, "packet_loss_percent": 0})
    }

    # Load notifications
    if NOTIFICATION_LOG.exists():
        with open(NOTIFICATION_LOG, "r") as f:
            for line in f:
                try:
                    notif = json.loads(line.strip())
                    app = notif.get("app_name", "unknown_app")
                    result["apps"][app]["notifications"] += 1
                except:
                    continue

    try:
        # Ensure event loop is set up
        cap = pyshark.FileCapture(str(PCAP_OUTPUT), keep_packets=True)

        first_seen = {}
        last_seen = {}
        packet_count = defaultdict(int)

        for pkt in cap:
            if not hasattr(pkt, "ip"):
                continue
            pkt_time = float(pkt.sniff_timestamp)
            for app_name in result["apps"]:
                if app_name not in first_seen:
                    first_seen[app_name] = pkt_time
                last_seen[app_name] = pkt_time
                packet_count[app_name] += 1

                if hasattr(pkt, "tls"):
                    tls_version = TLS_VERSIONS.get(pkt.tls.record_version, None) if hasattr(pkt.tls, "record_version") else None
                    cipher = pkt.tls.ciphersuite if hasattr(pkt.tls, "ciphersuite") else None
                    # Calculate the score for this TLS session
                    score = calculate_score(
                        delay_ms=(last_seen[app_name] - first_seen[app_name]) * 1000,  # ms
                        packet_loss_percent=0,  # Placeholder for actual packet loss logic
                        tls_version=tls_version,
                        cipher=cipher
                    )
                    result["apps"][app_name]["tls_sessions"].append({
                        "src": pkt.ip.src,
                        "dst": pkt.ip.dst,
                        "tls_version": tls_version,
                        "cipher": cipher,
                        "score": score
                    })

        cap.close()

        # Compute per-app metrics
        for app_name in result["apps"]:
            if app_name in first_seen and app_name in last_seen:
                result["apps"][app_name]["avg_delay_ms"] = (last_seen[app_name] - first_seen[app_name]) * 1000
            else:
                result["apps"][app_name]["avg_delay_ms"] = 0
            result["apps"][app_name]["packet_loss_percent"] = 0  # placeholder for future packet loss logic

        # Overall metrics
        delays = [v["avg_delay_ms"] for v in result["apps"].values() if v["avg_delay_ms"] > 0]
        result["average_delay_ms"] = sum(delays) / len(delays) if delays else 0

        total_score = 0
        total_sessions = 0
        for app_data in result["apps"].values():
            for sess in app_data["tls_sessions"]:
                total_score += sess["score"]
                total_sessions += 1
        result["summary_score"] = total_score // total_sessions if total_sessions else 0

        # Convert apps to normal dict
        result["apps"] = dict(result["apps"])

    except Exception as e:
        print(f"[!] Error analyzing {PCAP_OUTPUT}: {e}")

    return result

if __name__ == "__main__":
    analyze_pcap()
