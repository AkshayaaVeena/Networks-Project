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

# Scoring for TLS versions
TLS_SCORING = {
    "TLS 1.0": 10,
    "TLS 1.1": 15,
    "TLS 1.2": 30,
    "TLS 1.3": 40
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
    (0, 50): 40,   
    (51, 100): 30,  
    (101, 200): 20, 
    (201, float('inf')): 10
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

# Scoring for certificate strength (dummy values for now)
CERTIFICATE_SCORING = {
    "Weak": 10,
    "Medium": 20,
    "Strong": 30
}

def score_cipher(cipher_name: str) -> int:
    cipher_name = cipher_name.upper()
    
    if 'TLS_AES' in cipher_name and 'GCM' in cipher_name:
        return 100  # TLS 1.3 AEAD
    elif 'CHACHA20' in cipher_name:
        return 95
    elif 'ECDHE' in cipher_name and 'GCM' in cipher_name:
        return 90
    elif 'ECDHE' in cipher_name and 'CBC' in cipher_name:
        return 70
    elif 'AES' in cipher_name and 'CBC' in cipher_name:
        return 60
    elif any(x in cipher_name for x in ['RC4', '3DES', 'MD5', 'NULL', 'EXPORT']):
        return 0
    else:
        return 50  # unknown or medium
def check_forward_secrecy(cipher):
    if "ECDHE" in cipher or "DHE" in cipher:
        return 40  # High score for forward secrecy
    return 0  # No forward secrecy

# Check if the certificate is self-signed or issued by a trusted CA (dummy check)
def check_certificate(cert):
    if cert == "self-signed":
        return "Weak"
    elif cert == "trusted":
        return "Strong"
    return "Medium"

def calculate_score(delay_ms, packet_loss_percent, tls_version, cipher, certificate_strength):
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
    cipher_score = score_cipher(cipher)
    
    # Certificate strength score
    cert_score = CERTIFICATE_SCORING.get(certificate_strength, 0)
    
    # Forward secrecy score
    fs_score = check_forward_secrecy(cipher)
    
    # Combine all factors for a final score, adjusting weights
    total_score = (delay_score * 0.1) + (packet_loss_score * 0.1) + (tls_score * 0.2) + (cipher_score * 0.2) + (cert_score * 0.2) + (fs_score * 0.2)
    
    return int(total_score)

def analyze_pcap():
    # Ensure that the event loop is available in this thread (for asyncio compatibility)
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

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
                    app = notif.get("app", "unknown_app")
                    result["apps"][app]["notifications"] += 1
                except:
                    continue

    try:
        # Create a separate event loop for the pyshark capture to avoid conflict
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

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
                    tls_version = None
                    cipher = None

                    # Check if tls layer exists
                    if hasattr(pkt.tls, 'record_version'):
                        tls_version = TLS_VERSIONS.get(pkt.tls.record_version, "Unknown TLS Version")
                    
                    # Check if cipher info exists
                   # print(pkt.tls)
                    #print(f"FieldNames : {pkt.tls.field_names}")
                    if(hasattr(pkt.tls,"handshake_ciphersuite")):
                        cipher = pkt.tls.handshake_ciphersuite.showname_value
                        cipher_score = score_cipher(cipher)
                     #   print(f"Handshake cipher suite : {pkt.tls.handshake_ciphersuite.showname}")
                        
                    
                    
                    # Only attempt to access cipher if it's available
                    if cipher is not None:
                        fs_score = check_forward_secrecy(cipher)
                    else:
                        fs_score = 0  # No cipher or forward secrecy available
                    
                    # TLS Version and Cipher Scoring
                    tls_score = TLS_SCORING.get(tls_version, 0)
                    #cipher_score = score_cipher(cipher)
                    
                    #cipher_score = CIPHER_SCORING.get(cipher, 0)

                    # Update the result for this app
                    result["apps"][app_name]["tls_sessions"].append({
                        "tls_version": tls_version,
                        "cipher": cipher,
                        "tls_score": tls_score,
                        "cipher_score": cipher_score,
                        "forward_secrecy_score": fs_score
                    })

        # Summarize overall score
        # Summarize overall score
       # print("Overall score calculation")
       # print(result["apps"].items())
        total_score = 0
        for app_name, app_data in result["apps"].items():  # Unpacking key (app_name) and value (app_data)
            print("Sessions processing")
            app_score = 0
            for session in app_data["tls_sessions"]:  # Accessing tls_sessions from app_data
                app_score += session["tls_score"] + session["cipher_score"] + session["forward_secrecy_score"]
                app_score = app_score / len(app_data["tls_sessions"]) if app_data["tls_sessions"] else 0
            result["apps"][app_name]["score"] = app_score
            total_score += app_score

        result["summary_score"] = total_score / len(result["apps"]) if result["apps"] else 0
        
        #total_score = 0
        #for app_name in result["apps"].items():
        #    print("Sessions processing")
        #    app_score = 0
        #    for session in app_name["tls_sessions"]:
        #        app_score += session["tls_score"] + session["cipher_score"] + session["forward_secrecy_score"]
        #    app_score = app_score / len(app_name["tls_sessions"]) if app_name["tls_sessions"] else 0
        #    result["apps"][app_name]["score"] = app_score
        #    total_score += app_score

        #result["summary_score"] = total_score / len(result["apps"]) if result["apps"] else 0

    except Exception as e:
        print(f"[!] Error analyzing captures: {type(e).__name__}: {str(e)}")
        result["error"] = f"{type(e).__name__}: {str(e)}"
    return result