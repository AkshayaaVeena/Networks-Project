import asyncio
import pyshark
from collections import defaultdict
import json
from config import PCAP_OUTPUT, NOTIFICATION_LOG

TLS_VERSIONS = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3"
}

TLS_SCORING = {
    "TLS 1.0": 10,
    "TLS 1.1": 15,
    "TLS 1.2": 30,
    "TLS 1.3": 40
}

CERTIFICATE_SCORING = {
    "Weak": 10,
    "Medium": 20,
    "Strong": 30
}

SUSPICIOUS_DOMAINS = {"tracker.com", "malicious.site", "ads.example"}

def score_cipher(cipher_name: str) -> int:
    if cipher_name is None:
        return 0
    cipher_name = cipher_name.upper()
    if 'TLS_AES' in cipher_name and 'GCM' in cipher_name:
        return 40
    elif 'CHACHA20' in cipher_name:
        return 30
    elif 'ECDHE' in cipher_name and 'GCM' in cipher_name:
        return 20
    elif 'ECDHE' in cipher_name and 'CBC' in cipher_name:
        return 15
    elif 'AES' in cipher_name and 'CBC' in cipher_name:
        return 10
    elif any(x in cipher_name for x in ['RC4', '3DES', 'MD5', 'NULL', 'EXPORT']):
        return 5
    else:
        return 0

def check_forward_secrecy(cipher):
    if cipher and ("ECDHE" in cipher or "DHE" in cipher):
        return 20
    return 0

def check_certificate(cert):
    if cert == "self-signed":
        return "Weak"
    elif cert == "trusted":
        return "Strong"
    return "Medium"

def is_suspicious_domain(domain: str) -> bool:
    return domain.lower() in SUSPICIOUS_DOMAINS

def calculate_app_score(app_data):
    sessions = app_data["tls_sessions"]
    if not sessions:
        return 0

    total = 0
    for session in sessions:
        tls_score = TLS_SCORING.get(session["tls_version"], 0)
        cipher_score = score_cipher(session["cipher"])
        fs_score = check_forward_secrecy(session["cipher"])
        cert_score = CERTIFICATE_SCORING.get(session.get("certificate_strength", "Medium"), 20)
        insecure_penalty = -10 if session.get("uses_http", False) else 0
        suspicious_penalty = -5 if session.get("suspicious_domain", False) else 0

        session_score = (
            tls_score * 0.2 +
            cipher_score * 0.2 +
            fs_score * 0.15 +
            cert_score * 0.15 +
            insecure_penalty +
            suspicious_penalty
        )
        total += session_score

    avg_score = total / len(sessions)
    if app_data.get("quic_used", False):
        avg_score += 5

    normalized_score = (avg_score / 28.5) * 100
    normalized_score = max(0, min(100, int(normalized_score)))

    return normalized_score

def analyze_pcap():
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    result = {
        "summary_score": 0,
        "apps": defaultdict(lambda: {
            "notifications": 0,
            "tls_sessions": [],
            "quic_used": False,
            "score": 0,
            "domains_contacted": set(),
            "packet_loss": 0.0,
            "average_delay": 0.0
        })
    }

    if NOTIFICATION_LOG.exists():
        with open(NOTIFICATION_LOG, "r") as f:
            for line in f:
                try:
                    notif = json.loads(line.strip())
                    app = notif.get("app", "unknown_app")
                    result["apps"][app]["notifications"] += 1
                except json.JSONDecodeError:
                    continue

    try:
        cap = pyshark.FileCapture(str(PCAP_OUTPUT), keep_packets=False)
        tcp_flows = defaultdict(lambda: {"seq": set(), "ack_times": [], "syn_time": None, "synack_time": None})

        for pkt in cap:
            if not hasattr(pkt, "ip"):
                continue

            if hasattr(pkt, "tcp"):
                src = pkt.ip.src
                dst = pkt.ip.dst
                sport = pkt.tcp.srcport
                dport = pkt.tcp.dstport
                flow_id = f"{src}:{sport}->{dst}:{dport}"

                seq = getattr(pkt.tcp, "seq", None)
                if seq:
                    tcp_flows[flow_id]["seq"].add(int(seq))

                if "SYN" in pkt.tcp.flags and "ACK" not in pkt.tcp.flags:
                    tcp_flows[flow_id]["syn_time"] = float(pkt.sniff_timestamp)
                elif "SYN" in pkt.tcp.flags and "ACK" in pkt.tcp.flags:
                    tcp_flows[flow_id]["synack_time"] = float(pkt.sniff_timestamp)

            for app_name in result["apps"]:
                session = {
                    "tls_version": "Unknown",
                    "cipher": None,
                    "certificate_strength": "Medium",
                    "uses_http": False,
                    "suspicious_domain": False
                }

                if hasattr(pkt, "tls"):
                    tls_version = getattr(pkt.tls, 'record_version', '')
                    session["tls_version"] = TLS_VERSIONS.get(tls_version, "Unknown")
                    cipher = getattr(pkt.tls, 'handshake_ciphersuite', None)
                    session["cipher"] = cipher.showname_value if cipher else None

                    sni = getattr(pkt.tls, 'handshake_extensions_server_name', None)
                    if sni:
                        session["sni"] = sni
                        result["apps"][app_name]["domains_contacted"].add(sni)
                        session["suspicious_domain"] = is_suspicious_domain(sni)

                    cert_field = getattr(pkt.tls, 'handshake_certificate', None)
                    if cert_field:
                        cert_type = "trusted" if "CA" in cert_field.showname else "self-signed"
                        session["certificate_strength"] = check_certificate(cert_type)

                    result["apps"][app_name]["tls_sessions"].append(session)

                elif hasattr(pkt, "quic"):
                    result["apps"][app_name]["quic_used"] = True

                elif hasattr(pkt, "http") and not hasattr(pkt, "tls"):
                    session["uses_http"] = True
                    session["tls_version"] = "None"
                    result["apps"][app_name]["tls_sessions"].append(session)

        total_loss = 0
        total_delay = 0
        flow_count = len(tcp_flows)

        for flow_id, info in tcp_flows.items():
            seq_nums = sorted(list(info["seq"]))
            if len(seq_nums) > 1:
                expected_packets = seq_nums[-1] - seq_nums[0]
                received_packets = len(seq_nums)
                loss_percent = 100 * (1 - (received_packets / max(expected_packets, 1)))
                total_loss += max(0, loss_percent)

            if info["syn_time"] and info["synack_time"]:
                delay = info["synack_time"] - info["syn_time"]
                total_delay += delay

        avg_loss = total_loss / flow_count if flow_count else 0
        avg_delay = total_delay / flow_count if flow_count else 0

        for app_data in result["apps"].values():
            app_data["packet_loss"] = round(avg_loss, 2)
            app_data["average_delay"] = round(avg_delay, 4)

        total_score = 0
        for app_name, app_data in result["apps"].items():
            app_data["score"] = calculate_app_score(app_data)
            app_data["domains_contacted"] = list(app_data["domains_contacted"])
            total_score += app_data["score"]

        result["summary_score"] = total_score / len(result["apps"]) if result["apps"] else 0

    except Exception as e:
        print(f"[!] Error analyzing captures: {type(e).__name__}: {str(e)}")
        result["error"] = f"{type(e).__name__}: {str(e)}"

    return result
