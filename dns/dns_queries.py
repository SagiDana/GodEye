from scapy.layers.dns import DNSRR, DNS, DNSQR
from datetime import datetime, timedelta
from scapy.all import *


class DnsQuery:
    def __init__(self, question, answer):
        self.question = question
        self.answer = answer
        self.time = datetime.now()


class DnsRepository:
    _instance = None

    @staticmethod
    def get_instance():
        if not DnsRepository._instance:
            DnsRepository._instance = DnsRepository()
        return DnsRepository._instance

    def __init__(self):
        self.queries = {}
    
    def __clean_repository(self):
        new_queries = {}
        now = datetime.now()

        for key in self.queries:
            if now - self.queries[key].time < timedelta(minutes=30):
                new_queries[key] = self.queries[key]

        self.queries = new_queries

    def on_packet_event(self, packet):
        p = packet.raw_packet

        if p.haslayer(DNSRR):
            for i in range(4, p[DNS].ancount + 4):
                try:
                    question = p[1][i].rrname.decode()
                    answer = p[1][i].rdata

                    self.queries[answer] = DnsQuery(question, answer)      

                    self.__clean_repository()
                except Exception as e: pass

    def query(self, ip):
        self.__clean_repository()

        if ip in self.queries:
            return self.queries[ip].question
        return None
