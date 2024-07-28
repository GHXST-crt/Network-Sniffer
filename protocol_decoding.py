from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

class ProtocolDecoding:
    def __init__(self):
        pass

    def decode_packet(self, packet):
        details = {
            'Ethernet': packet[Ether].summary() if Ether in packet else '',
            'IP': packet[IP].summary() if IP in packet else '',
            'TCP': packet[TCP].summary() if TCP in packet else '',
            'UDP': packet[UDP].summary() if UDP in packet else '',
            'ICMP': packet[ICMP].summary() if ICMP in packet else '',
            'ARP': packet[ARP].summary() if ARP in packet else '',
            'DNS': packet[DNS].summary() if DNS in packet else ''
        }
        return details
