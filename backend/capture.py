import subprocess
from pathlib import Path
import config

CAP_DIR = Path("captures")
CAP_DIR.mkdir(parents=True, exist_ok=True)
NETWORK_INTERFACE = "Ethernet"
def capture_notifications(output_file=config.PCAP_OUTPUT, duration=config.CAPTURE_DURATION):
    """
    Captures push notification traffic from Android phone via tshark.
    """
    cmd = [
        "tshark",
        "-i", config.NETWORK_INTERFACE,
        "-a", f"duration:{duration}",
        "-f", config.CAPTURE_FILTER,
        "-w", output_file
    ]
    print(f"📡 Capturing notifications for {duration}s on {config.NETWORK_INTERFACE}...")
    subprocess.run(cmd, check=True)
    print(f"✅ Capture saved to {output_file}")
    return output_file

