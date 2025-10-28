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
        return {"score": 0, "session_details": []}

    total = 0
    valid_sessions = 0
    session_details = []

    for session in sessions:
        if session["tls_version"] in ("Unknown", "None") and not session["cipher"]:
            session_details.append({
                "tls_version": session["tls_version"],
                "cipher": session["cipher"],
                "certificate_strength": session.get("certificate_strength", "Medium"),
                "uses_http": session.get("uses_http", False),
                "suspicious_domain": session.get("suspicious_domain", False),
                "session_score": 0,
                "note": "Skipped - no TLS/cipher info"
            })
            continue

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
        valid_sessions += 1

        session_details.append({
            "tls_version": session["tls_version"],
            "cipher": session["cipher"],
            "certificate_strength": session.get("certificate_strength", "Medium"),
            "uses_http": session.get("uses_http", False),
            "suspicious_domain": session.get("suspicious_domain", False),
            "session_score": round(session_score, 2),
            "note": "Valid session"
        })

    avg_score = total / valid_sessions if valid_sessions else 0

    if app_data.get("quic_used", False):
        avg_score += 5

    max_possible = (
        TLS_SCORING["TLS 1.3"] * 0.2 +
        40 * 0.2 +
        20 * 0.15 +
        CERTIFICATE_SCORING["Strong"] * 0.15
    )

    normalized_score = int(max(0, min(100, (avg_score / max_possible) * 100)))
    return {"score": normalized_score, "session_details": session_details}

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
                except:
                    continue

    app_flows = defaultdict(lambda: defaultdict(lambda: {"seq": set(), "syn_time": None, "synack_time": None}))

    try:
        cap = pyshark.FileCapture(str(PCAP_OUTPUT), keep_packets=False)
        for pkt in cap:
            if not hasattr(pkt, "ip"):
                continue

            app_name = "unknown_app"
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                sni = getattr(pkt.tls, "handshake_extensions_server_name")
                if sni:
                    app_name = sni.split('.')[0]  
            elif hasattr(pkt, "http"):
                host = getattr(pkt.http, "host", None)
                if host:
                    app_name = host.split('.')[0]

            if hasattr(pkt, "tcp"):
                src = pkt.ip.src
                dst = pkt.ip.dst
                sport = pkt.tcp.srcport
                dport = pkt.tcp.dstport
                flow_id = f"{src}:{sport}->{dst}:{dport}"

                seq = getattr(pkt.tcp, "seq", None)
                if seq:
                    app_flows[app_name][flow_id]["seq"].add(int(seq))

                flags = getattr(pkt.tcp, "flags", "")
                if "SYN" in flags and "ACK" not in flags:
                    app_flows[app_name][flow_id]["syn_time"] = float(pkt.sniff_timestamp)
                elif "SYN" in flags and "ACK" in flags:
                    app_flows[app_name][flow_id]["synack_time"] = float(pkt.sniff_timestamp)

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
                    session["suspicious_domain"] = is_suspicious_domain(sni)
                    result["apps"][app_name]["domains_contacted"].add(sni)

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

        for app_name, flows in app_flows.items():
            total_loss = 0
            total_delay = 0
            flow_count = len(flows)

            for flow_id, info in flows.items():
                seq_nums = sorted(list(info["seq"]))
                if len(seq_nums) > 1:
                    expected_packets = seq_nums[-1] - seq_nums[0]
                    received_packets = len(seq_nums)
                    loss_percent = 100 * (1 - (received_packets / max(expected_packets, 1)))
                    total_loss += max(0, loss_percent)
                if info["syn_time"] and info["synack_time"]:
                    total_delay += info["synack_time"] - info["syn_time"]

            result["apps"][app_name]["packet_loss"] = round(total_loss / flow_count, 2) if flow_count else 0
            result["apps"][app_name]["average_delay"] = round(total_delay / flow_count, 4) if flow_count else 0

        total_score = 0
        for app_name, app_data in result["apps"].items():
            app_result = calculate_app_score(app_data)
            app_data["score"] = app_result["score"]
            app_data["session_details"] = app_result["session_details"]
            app_data["domains_contacted"] = list(app_data["domains_contacted"])
            total_score += app_result["score"]

        app_count = len(result["apps"])
        result["summary_score"] = total_score / app_count if app_count else 0

    except Exception as e:
        print(f"[!] Error analyzing captures: {type(e).__name__}: {str(e)}")
        result["error"] = f"{type(e).__name__}: {str(e)}"

    return result
