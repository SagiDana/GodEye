from dns.dns_queries import *
from scapy.all import *
from packets import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from netifaces import interfaces, ifaddresses, AF_INET

class Control:
    def __init__(self):
        pass

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

        if self.__is_packet_dns(packet): 
            DnsRepository.get_instance().on_packet_event(packet)
        
        answer = DnsRepository.get_instance().query(packet.remote_ip)
        
        print("[-] [{}]{}: {} -> {}".format(packet.protocol, packet.process, packet.remote_ip, answer))

