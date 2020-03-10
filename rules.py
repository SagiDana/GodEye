
class Rule:
    def __init__(self):
        pass

    def is_match(self, packet):
        pass

from dns.dns_queries import *
import socket
class RootProcessWhiteListDomainsRule:
    def __init__(self, domains):
        self.domains = domains

    def is_match(self, packet):
        if packet.process != "pid: -1": return False

        try:
            domain = DnsRepository.get_instance().query(packet.remote_ip)

            if not domain: 
                domain = socket.gethostbyaddr(packet.remote_ip)[0]

            for current_domain in self.domains:
                if current_domain in domain: 
                    return True

        except: pass

        return False

class ApplicationsToRemotePortsRule:
    def __init__(self, applications, remote_ports):
        self.applications = applications
        self.remote_ports = remote_ports

    def is_match(self, packet):
        for app in self.applications:
            if app not in packet.process: continue

            for port in self.remote_ports:
                if packet.remote_port != port: continue
                return True
        return False

class AllowMulticastAddressesRule:
    def __init__(self): pass

    def is_match(self, packet):
        if packet.process != "pid: -1": return False

        if packet.remote_ip.startswith("224"): return True
        if packet.remote_ip.startswith("239"): return True

        return False
