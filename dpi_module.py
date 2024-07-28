from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

class DPI:
    def __init__(self):
        pass

    def analyze_packet(self, packet):
        analysis = {
            'src_ip': packet[IP].src if IP in packet else '',
            'dst_ip': packet[IP].dst if IP in packet else '',
            'protocol': packet.sprintf("%IP.proto%"),
            'length': len(packet),
        }
        if DNS in packet:
            analysis['dns_query'] = packet[DNSQR].qname if packet[DNS].qr == 0 else ''
            analysis['dns_response'] = packet[DNSRR].rdata if packet[DNS].qr == 1 else ''
        if TCP in packet:
            analysis.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet.sprintf("%TCP.flags%")
            })
        if UDP in packet:
            analysis.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        if ICMP in packet:
            analysis.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code
            })
        if ARP in packet:
            analysis.update({
                'src_mac': packet[ARP].hwsrc,
                'dst_mac': packet[ARP].hwdst,
                'opcode': packet[ARP].op
            })
        return analysis
