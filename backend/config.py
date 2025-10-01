# Network interface connected to phone via USB tether or hotspot
NETWORK_INTERFACE = "Ethernet"  # replace with your tshark interface name

# Capture filter (push notification traffic, typically FCM)
CAPTURE_FILTER = "tcp port 443"

# Location to save captured .pcap files
PCAP_OUTPUT = "captures/update_channel.pcap"

# Capture duration in seconds
CAPTURE_DURATION = 30  # capture each batch for 30s

# Security thresholds
TLS_MIN_VERSION = "TLS 1.2"
STRONG_CIPHER_SUITES = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
]

LATENCY_THRESHOLDS = {"good": 200, "medium": 500}      # in ms
PACKET_LOSS_THRESHOLDS = {"good": 1, "medium": 5}      # in %
