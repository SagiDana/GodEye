#!/usr/bin/python
# from windows import get_process_from_connection
from process.linux import get_process_from_connection
from threading import Thread, Event
from packets import PacketEvent
from scapy.all import *
from control import *
from osd_cat import Osd

class GodEye:
    @staticmethod
    def catch_packet(self):
        def __catch_packet(packet):
            ip_layer = packet.getlayer(IP)
            tcp_layer = packet.getlayer(TCP)
            udp_layer = packet.getlayer(UDP)

            p = None
            process = None
            if tcp_layer:
                process = get_process_from_connection([ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport])
                # print("[!] -[{process}]- ({length}): TCP -> {src}:{src_port} -> {dst}:{dst_port}".format(process=process,
                        # length=len(packet), 
                        # src=ip_layer.src, 
                        # dst=ip_layer.dst, 
                        # src_port=tcp_layer.sport, 
                        # dst_port=tcp_layer.dport))

                p = PacketEvent(process, ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, len(packet), 'tcp', packet)
            elif udp_layer:
                process = get_process_from_connection([ip_layer.src, ip_layer.dst, udp_layer.sport, udp_layer.dport])
                # print("[!] -[{process}]- ({length}): UDP -> {src}:{src_port} -> {dst}:{dst_port}".format(process=process, 
                    # length=len(packet), 
                    # src=ip_layer.src, 
                    # dst=ip_layer.dst, 
                    # src_port=udp_layer.sport, 
                    # dst_port=udp_layer.dport))
                p = PacketEvent(process, ip_layer.src, udp_layer.sport, ip_layer.dst, udp_layer.dport, len(packet), 'udp', packet)

            if not p: return

            #TODO: Logic
            self.control.process_packet(p)

        return __catch_packet

    @staticmethod
    def _start_sniff(self):
        sniff(filter="ip", prn=GodEye.catch_packet(self), stop_filter=lambda p: self.event.is_set())

    def __init__(self):
        self.event = Event()
        self.osd = Osd()
        self.control = Control(self.osd)
        self.thread = None

    def start(self):
        self.osd.open()
        self.thread = Thread(target=GodEye._start_sniff, args=(self,))
        self.thread.start()

    def stop(self):
        self.event.set()
        self.thread.join()
        self.event.clear()
        self.thread = None
        self.osd.close()


if __name__ == "__main__":
    godeye = GodEye()

    godeye.start()

    while True:
        try:
            _ = input()
        except KeyboardInterrupt as e:
            break
        except:
            continue

    godeye.stop()
