from config import STRONG_CIPHER_SUITES, LATENCY_THRESHOLDS, PACKET_LOSS_THRESHOLDS

def score_channel(tls_version, cipher, cert_valid, latency_ms, packet_loss, **kwargs):
    score = 0

    # TLS Version
    if tls_version and "1.3" in tls_version:
        score += 20
    elif tls_version and "1.2" in tls_version:
        score += 10

    # Cipher Suite
    if cipher and any(c in cipher for c in STRONG_CIPHER_SUITES):
        score += 20

    # Certificate validity
    if cert_valid:
        score += 20

    # Latency
    if latency_ms < LATENCY_THRESHOLDS["good"]:
        score += 20
    elif latency_ms < LATENCY_THRESHOLDS["medium"]:
        score += 10

    # Packet loss
    if packet_loss < PACKET_LOSS_THRESHOLDS["good"]:
        score += 20
    elif packet_loss < PACKET_LOSS_THRESHOLDS["medium"]:
        score += 10

    return score

