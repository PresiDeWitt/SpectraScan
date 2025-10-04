#!/usr/bin/env python3
"""
Host discovery module
"""

import socket
import subprocess
import requests
from utils import network
from datetime import datetime


class HostDiscovery:
    def __init__(self):
        self.live_hosts = set()
        self.discovered_hosts = {}  # Para almacenar información adicional

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
                    self._register_host(target, f"tcp_{port}")
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
                self._register_host(target, f"udp_{port}")
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
                    self._register_host(target, f"{scheme}_web")
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
                self._register_host(target, "icmp")
                return True
        except:
            pass
        return False

    def _register_host(self, target, method):
        """Register discovered host with OS fingerprinting"""
        self.live_hosts.add(target)

        if target not in self.discovered_hosts:
            self.discovered_hosts[target] = {
                'discovery_methods': [method],
                'os_guess': network.os_fingerprint(target),
                'first_seen': datetime.now().isoformat()
            }
        else:
            self.discovered_hosts[target]['discovery_methods'].append(method)

        print(f"[+] HOST DISCOVERED: {target} via {method}")

    def get_host_info(self, target):
        """Get information about a discovered host"""
        return self.discovered_hosts.get(target, {})