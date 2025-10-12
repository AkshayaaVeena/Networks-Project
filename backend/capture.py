import asyncio
import pyshark
from config import PCAP_OUTPUT, CAPTURE_INTERFACE

def capture_packets():
    # Ensure an event loop is set up for this thread
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError as e:
        if str(e).startswith('There is no current event loop in thread'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        else:
            raise  # Raise if there's an unexpected error

    # Create the live capture object
    capture = pyshark.LiveCapture(interface=CAPTURE_INTERFACE, output_file=str(PCAP_OUTPUT))
    print(f"[+] Starting capture for 20 seconds on {CAPTURE_INTERFACE}...")

    # Start sniffing packets
    try:
        capture.sniff(timeout=20)  # Sniff for 20 seconds
        print(f"[+] Capture complete: {PCAP_OUTPUT}")
    except Exception as e:
        print(f"[!] Capture error: {e}")
    finally:
        capture.close()

if __name__ == "__main__":
    capture_packets()
