class FirewallTesting:
    def __init__(self):
        pass

    def test(self, packets):
        results = []
        for packet in packets:
            if TCP in packet and packet[TCP].flags == 'S':
                results.append(f"Potential Firewall Test: {packet.summary()}")
        return results
