from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

print("Starting Packet capture...!")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        src_port = None
        dst_port = None
        payload_data = None
        protocol = packet[IP].proto

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload_data = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload_data = bytes(packet[UDP].payload)

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
        print(f"Protocol: {protocol}")

        if payload_data:
            print(f"Payload: {payload_data[:20]}...")  # print first 20 bytes

# Capture 10 packets
sniff(prn=packet_callback, count=10)
print("Stopping packet capture...!")