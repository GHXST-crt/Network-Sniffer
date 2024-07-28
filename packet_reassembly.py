from scapy.all import *

class PacketReassembler:
    def __init__(self):
        self.fragments = {}

    def reassemble(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            if ip_layer.flags == 1:  # More fragments flag
                self.fragments[ip_layer.id] = self.fragments.get(ip_layer.id, []) + [ip_layer]
                return None
            elif ip_layer.id in self.fragments:
                fragments = self.fragments.pop(ip_layer.id)
                fragments.append(ip_layer)
                reassembled_packet = fragments[0]
                for frag in fragments[1:]:
                    reassembled_packet = reassembled_packet / frag.payload
                return reassembled_packet
        return packet
