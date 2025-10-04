#!/usr/bin/env python3
"""
Main scanner core module
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.discovery import HostDiscovery
from core.analyzer import ServiceAnalyzer
from config import ports, settings


class NetworkScanner:
    def __init__(self):
        self.results = {
            'scan_metadata': {
                'scanner_version': settings.SCANNER_VERSION,
                'scan_type': 'comprehensive',
                'timestamp': None
            },
            'network_summary': {},
            'hosts': {},
            'vulnerabilities': [],
            'recommendations': [],
            'risk_assessment': {}
        }

        self.discovery = HostDiscovery()
        self.analyzer = ServiceAnalyzer()
        self.thread_lock = threading.Lock()

    def comprehensive_service_scan(self, target):
        """Comprehensive service scanning with security assessment"""
        print(f"[*] SERVICE SCAN: Comprehensive scan: {target}")

        open_ports = []
        for port in ports.COMPREHENSIVE_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(settings.DEFAULT_TIMEOUT)
                result = sock.connect_ex((target, port))

                if result == 0:
                    service_info = self.analyzer.analyze_service(target, port)
                    open_ports.append(port)

                    with self.thread_lock:
                        if 'ports' not in self.results['hosts'][target]:
                            self.results['hosts'][target]['ports'] = {}
                        self.results['hosts'][target]['ports'][port] = service_info

                    print(f"  [+] SERVICE: {target}:{port} - {service_info['service']}")

                sock.close()

            except Exception as e:
                print(f"  [-] SCAN ERROR: {target}:{port} - {e}")

        return open_ports