import asyncio
import pyshark
from config import PCAP_OUTPUT, CAPTURE_INTERFACE, CAPTURE_DURATION_SECONDS

def ensure_directory_exists(file_path):
    output_dir = file_path.parent
    if not output_dir.exists():
        print(f"[!] Directory {output_dir} does not exist. Creating...")
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        print(f"[+] Directory {output_dir} exists.")

def capture_packets():
    ensure_directory_exists(PCAP_OUTPUT)

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError as e:
        if str(e).startswith('There is no current event loop in thread'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        else:
            raise

    capture = pyshark.LiveCapture(interface=CAPTURE_INTERFACE, output_file=str(PCAP_OUTPUT))
    print(f"[+] Starting capture for {CAPTURE_DURATION_SECONDS} seconds on {CAPTURE_INTERFACE}...")

    try:
        capture.sniff(timeout=CAPTURE_DURATION_SECONDS)
        print(f"[+] Capture complete: {PCAP_OUTPUT}")
    except Exception as e:
        print(f"[!] Capture error: {e}")
        raise
    finally:
        capture.close()

if __name__ == "__main__":
    capture_packets()
