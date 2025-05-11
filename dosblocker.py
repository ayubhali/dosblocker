import os
import sys
import time 
from collections import defaultdict
from scapy.all import sniff, IP 

THRESHOLD = 40
print(f"THRESHOLD :{THRESHOLD}") #If ip sends more than 40 packets in 1 second we block it 

def packet_callback(packet): 
    src_ip = packet[IP].src
    packet_count[src_ip] += 1 

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            print(f"IP: {ip}, packet rate: {packet_rate}")
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0: #raw network traffic & modify system firewalls
        print("This script requires root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int)
    start_time = [time.time()]  # Stored in a list so it can be changed inside the function
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
