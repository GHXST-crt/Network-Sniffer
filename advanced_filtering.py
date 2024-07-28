class AdvancedFiltering:
    def filter(self, packets):
        filtered_packets = []
        for packet in packets:
            if packet.haslayer('IP'):
                filtered_packets.append(packet)
        return filtered_packets

    def custom_filter(self, packets, criteria):
        filtered_packets = []
        for packet in packets:
            if criteria in packet.summary():
                filtered_packets.append(packet)
        return filtered_packets

    def display_filtered(self, packets):
        return [packet.summary() for packet in packets]
