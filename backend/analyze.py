import asyncio
import os
import pyshark
from analyzer.scoring import score_channel
import config

def analyze_capture(pcap_file=config.PCAP_OUTPUT):
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(pcap_file, display_filter="tls", use_json=True, include_raw=True)

    tls_version = None
    cipher = None
    cert_valid = True
    latencies = []
    packet_count = 0
    prev_time = None

    for pkt in cap:
        packet_count += 1
        if "TLS" in pkt:
            if hasattr(pkt.tls, "record_version"):
                tls_version = pkt.tls.record_version
            if hasattr(pkt.tls, "handshake_ciphersuite"):
                cipher = pkt.tls.handshake_ciphersuite

        if prev_time:
            latency = float(pkt.sniff_time.timestamp()) - float(prev_time)
            latencies.append(latency)
        prev_time = pkt.sniff_time.timestamp()

    avg_latency = (sum(latencies)/len(latencies))*1000 if latencies else 0
    packet_loss = max(0, (packet_count - len(latencies))/packet_count * 100 if packet_count else 0)

    results = {
        "tls_version": tls_version or "N/A",
        "cipher": cipher or "N/A",
        "cert_valid": cert_valid,
        "latency_ms": round(avg_latency, 2),
        "packet_loss": round(packet_loss, 2)
    }

    results["score"] = score_channel(**results)
    return results
