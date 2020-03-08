from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

class DnsQuery:
    def __init__(self, question, answer):
        self.question = question
        self.answer = answer


class DnsRepository:
    _instance = None

    def __init__(self):
        self.queries = {}
    
    @staticmethod
    def get_instance():
        if not DnsRepository._instance:
            DnsRepository._instance = DnsRepository()
        return DnsRepository._instance

    def on_packet_event(self, packet):
        p = packet.raw_packet

        if p.qdcount > 0 and isinstance(p.qd, DNSQR):
            name = p.qd.qname
            print("[-] DNSQR: {}:{} -> {}".format(p['IP'].src, p['IP'].dst, name))

        if p.haslayer(DNSRR):
            for i in range(4, p[DNS].ancount + 4):
                try:
                    question = p[1][i].rrname
                    answer = p[1][i].rdata
                    print("[-] DNSRR: question: {}, answer: {}".format(question, answer))

                    self.queries[answer] = DnsQuery(question, answer)      
                except Exception as e: pass

    def query(self, ip):
        if ip in self.queries:
            # print("[-] for ip {} -> {}".format(ip, self.queries[ip].question))
            return self.queries[ip].question
        return None
