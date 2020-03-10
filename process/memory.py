from datetime import datetime, timedelta

class ProcessEntry:
    def __init__(self, process, packet):
        self.process = process
        self.packet = packet

        self.time = datetime.now()


class ProcessMemory:
    _instance = None

    @staticmethod
    def get_instance():
        if not ProcessMemory._instance:
            ProcessMemory._instance = ProcessMemory()
        return ProcessMemory._instance

    def __init__(self): 
        self.repo = {}
    
    def __clean_repository(self):
        new_repo = {}
        now = datetime.now()
        for key in self.repo:
            if now - self.repo[key].time < timedelta(minutes=20):
                new_repo[key] = self.repo[key]
        self.repo = new_repo

    def __packet_to_uid(self, packet):
        return "{}:{}->{}:{}".format(
                                        packet.local_ip,
                                        packet.local_port,
                                        packet.remote_ip,
                                        packet.remote_port,
                                    )

    def query(self, packet):
        self.__clean_repository()

        packet_id = self.__packet_to_uid(packet)

        if packet.process != "pid: -1":
            self.repo[packet_id] = ProcessEntry(packet.process, packet)
            return packet

        if packet_id not in self.repo: 
            return packet

        packet.process = self.repo[packet_id].process
        return packet
