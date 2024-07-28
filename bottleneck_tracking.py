class BottleneckTracking:
    def __init__(self):
        pass

    def track(self, packets):
        bottlenecks = []
        packet_counts = {}
        for packet in packets:
            src_ip = packet[IP].src if IP in packet else ''
            if src_ip:
                packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1

        sorted_counts = sorted(packet_counts.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_counts[:10]:  # Top 10 sources
            bottlenecks.append(f"IP: {ip}, Packet Count: {count}")
        return bottlenecks
