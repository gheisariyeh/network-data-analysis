import os
import pyshark
import time
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

def analyze_pcap(pcap_file):
    time_counter = Counter()  # To count packets per hour

    start_time = time.time()  # Start timer at beginning of function
    
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="ip")
        
        for packet in capture:
            try:
                # Extract timestamp and count by hour
                timestamp = datetime.fromtimestamp(float(packet.sniff_time.timestamp()))
                time_counter[timestamp.strftime('%H')] += 1
                
            except AttributeError:
                # Skip packets without IP or timestamp info
                continue
        
        capture.close()
    
    except Exception as e:
        print(f"Error analyzing pcap file: {e}")

    # Print packet count by hour
    print("Packet Count by Hour:", time_counter)
    
    end_time = time.time()  # End timer
    print(f"Analysis took {end_time - start_time:.2f} seconds")

# PCAP file path
pcap_file = "Path to the PCAP file"
if pcap_file == "Path to the PCAP file":
    raise ValueError("⚠️ Please set `pcap_file` to the actual path of your .pcap file before running.")
analyze_pcap(pcap_file)
