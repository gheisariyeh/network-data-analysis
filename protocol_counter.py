from scapy.all import rdpcap, TCP, UDP, ICMP, ARP
import time

# PCAP file path
pcap_file = "Path to the PCAP file"
if pcap_file == "Path to the PCAP file":
    raise ValueError("⚠️ Please set `pcap_file` to the actual path of your .pcap file before running.")

# Record start time
start_time = time.time()

# Read packets from the PCAP file
packets = rdpcap(pcap_file)

# Initialize counters for each protocol
protocol_counts = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'ARP': 0,
}

# Process each packet and increment the appropriate counter
for packet in packets:
    if packet.haslayer(TCP):
        protocol_counts['TCP'] += 1
    elif packet.haslayer(UDP):
        protocol_counts['UDP'] += 1
    elif packet.haslayer(ICMP):
        protocol_counts['ICMP'] += 1
    elif packet.haslayer(ARP):
        protocol_counts['ARP'] += 1

# Record end time and compute execution duration
end_time = time.time()
execution_time = end_time - start_time

# Print results
print("Packet counts by protocol:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

# Print execution duration
print(f"\nProgram execution time: {execution_time:.4f} seconds")
