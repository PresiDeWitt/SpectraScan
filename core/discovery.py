#!/usr/bin/env python3
"""
Host discovery module
"""

import socket
import subprocess
import requests
from utils import network, helpers

class HostDiscovery:
    def __init__(self):
        self.live_hosts = set()

    def advanced_host_discovery(self, target):
        """Multi-method host discovery"""
        methods = [
            self.tcp_port_discovery,
            self.udp_port_discovery,
            self.http_discovery,
            self.icmp_discovery
        ]

        for method in methods:
            if method(target):
                return True
        return False

    def tcp_port_discovery(self, target):
        """TCP-based host discovery"""
        from config.ports import DISCOVERY_PORTS_TCP
        for port in DISCOVERY_PORTS_TCP:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    self.register_host(target, f"tcp_{port}")
                    return True
            except:
                pass
        return False

    def udp_port_discovery(self, target):
        """UDP-based host discovery"""
        from config.ports import DISCOVERY_PORTS_UDP
        for port in DISCOVERY_PORTS_UDP:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(b'', (target, port))
                sock.recvfrom(1024)
                sock.close()
                self.register_host(target, f"udp_{port}")
                return True
            except:
                pass
        return False

    def http_discovery(self, target):
        """HTTP/HTTPS-based discovery"""
        for scheme in ['http', 'https']:
            try:
                response = requests.get(f"{scheme}://{target}", timeout=2, verify=False)
                if response.status_code < 500:
                    self.register_host(target, f"{scheme}_web")
                    return True
            except:
                pass
        return False

    def icmp_discovery(self, target):
        """ICMP-based discovery (requires root)"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', target],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                self.register_host(target, "icmp")
                return True
        except:
            pass
        return False

    def register_host(self, target, method):
        """Register discovered host"""
        self.live_hosts.add(target)
        print(f"[+] HOST DISCOVERED: {target} via {method}")