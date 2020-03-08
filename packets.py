import datetime
import psutil
import socket
import struct
from netifaces import interfaces, ifaddresses, AF_INET

def get_local_networks():
    local_networks = []
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                ip = struct.unpack('=L',socket.inet_aton(snic.address))[0]
                mask = struct.unpack('=L',socket.inet_aton(snic.netmask))[0]
                local_networks.append([mask , ip & mask])
    return local_networks

def is_external(ip):
    for net in get_local_networks():
        netmask = net[0]
        valid = net[1]
        packet_ip = struct.unpack('=L',socket.inet_aton(ip))[0]

        if packet_ip & netmask == valid:
            return False

        if ip.startswith("192.168."):
            return False
        if ip.startswith("10."):
            return False
        if ip.startswith("224.0.0"):
            return False

    return True

def get_local_ips():
    ip_list = []
    for interface in interfaces():
        try:
            for link in ifaddresses(interface)[AF_INET]:
                ip_list.append(link['addr'])
        except: continue
    return ip_list

def is_local_ip(ip):
    return ip in get_local_ips()

class PacketEvent:
    def __init__(self, process, src_ip, src_port, dst_ip, dst_port, length, protocol, raw_packet):
        self.creation_time = datetime.datetime.now()
        self.process = process
        self.protocol = protocol
        self.length = length
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.raw_packet = raw_packet

        self.local_ip, self.local_port, self.remote_ip, self.remote_port = self.get_perspective()

    # deduce the direction of the packet.
    def get_perspective(self):
        if not is_local_ip(self.src_ip):
            return self.dst_ip, self.dst_port, self.src_ip, self.src_port
        return self.src_ip, self.src_port, self.dst_ip, self.dst_port
