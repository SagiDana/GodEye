class Flow:
    def __init__(self,packet, max_packets_in_record=5):
        self.record = []

    def __initialize_with_packet(self, packet):
        pass

    def is_match(self, packet):
        pass

    def append(self, packet):
        self.record.append(packet)

    def check_against_rules(self, rules):
        return False
