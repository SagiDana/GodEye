from dns.dns_queries import *
import socket
import re


class Rule:
    def __init__(self, args):
        self.process = args["process"]
        self.protocol = args["protocol"]
        self.local_ip = args["local_ip"]
        self.local_port = args["local_port"]
        self.local_domain = args["local_domain"]
        self.remote_ip = args["remote_ip"]
        self.remote_port = args["remote_port"]
        self.remote_domain = args["remote_domain"]
        self.comment = args["comment"]

    def is_match(self, packet):
        if not re.match(self.process, packet.process): return False
        if not re.match(self.protocol, packet.protocol): return False
        if not re.match(self.local_ip, packet.local_ip): return False
        if not re.match(self.local_port, str(packet.local_port)): return False

        # not exist at the moment...
        # if not re.match(self.local_domain, packet.local_domain): return False

        if not re.match(self.remote_ip, packet.remote_ip): return False
        if not re.match(self.remote_port, str(packet.remote_port)): return False

        remote_domain = DnsRepository.get_instance().query(packet.remote_ip)
        if not remote_domain: remote_domain = ""
        if not re.match(self.remote_domain, remote_domain): return False

        return True
        
