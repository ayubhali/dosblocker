import os
import sys
import time 
from collections import defaultdict
from scapy.all import sniff, IP 

packet_count = {}

packet_count["192.168.1.1"] += 1  # ❌ This gives an error!

print(packet_count)