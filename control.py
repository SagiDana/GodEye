from dns.dns_queries import *
from scapy.all import *
from packets import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from netifaces import interfaces, ifaddresses, AF_INET
from process.memory import ProcessMemory
from rules import Rule
import json


class Control:
    def __init__(self, osd):
        self.osd = osd
        self.__initialize_rules()

    def __initialize_rules(self):
        self.rules = []
        rules = []

        try:
            with open("rules.json") as rules_file:
                rules = json.loads(rules_file.read())
        except: pass

        for rule in rules:
            self.rules.append(Rule(rule))

    def __get_local_ips(self):
        ip_list = []
        for interface in interfaces():
            try:
                for link in ifaddresses(interface)[AF_INET]:
                    ip_list.append(link['addr'])
            except: continue
        return ip_list
    
    def __is_local_ip(self, ip):
        return ip in self.__get_local_ips()

    # is packet methods:
    def __is_packet_dns(self, packet):
        return packet.raw_packet.haslayer(DNS) or packet.raw_packet.haslayer(DNSRR) or packet.raw_packet.haslayer(DNSQR)

    def __is_packet_attached_to_me(self, packet):
        p = packet.raw_packet
        ips = self.__get_local_ips()
        
        for ip in ips:
            if packet.local_ip == ip: 
                return True

        return False
        

    def process_packet(self, packet):
        if not self.__is_packet_attached_to_me(packet): return

        packet = ProcessMemory.get_instance().query(packet)

        if self.__is_packet_dns(packet): 
            DnsRepository.get_instance().on_packet_event(packet)
        
        to_print = True
        for rule in self.rules: 
            if rule.is_match(packet): 
                to_print = False
        
        if to_print: 
            print("[{process}]-({length}):[{protocol}]->{src}:{src_port}->{dst}:{dst_port}[[{remote_domain}]]\n".format(
                                                                                                                process=packet.process,
                                                                                                                length=packet.length,
                                                                                                                protocol=packet.protocol,
                                                                                                                src=packet.src_ip,
                                                                                                                dst=packet.dst_ip,
                                                                                                                src_port=packet.src_port,
                                                                                                                dst_port=packet.dst_port,
                                                                                                                remote_domain=DnsRepository.get_instance().query(packet.remote_ip)
                                                                                                            )
                                                                                                        )

            self.osd.display("[{process}]-({length}):[TCP]->{src}:{src_port}->{dst}:{dst_port}[[{remote_domain}]]\n".format(
                                                                                                                    process=packet.process,
                                                                                                                    length=packet.length,
                                                                                                                    src=packet.src_ip,
                                                                                                                    dst=packet.dst_ip,
                                                                                                                    src_port=packet.src_port,
                                                                                                                    dst_port=packet.dst_port,
                                                                                                                    remote_domain=DnsRepository.get_instance().query(packet.remote_ip
                                                                                                                )))

