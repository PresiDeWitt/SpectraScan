#!/usr/bin/env python3
"""
Main scanner core module
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core.discovery import HostDiscovery
from core.analyzer import ServiceAnalyzer
from config import ports, settings
from utils import network, helpers


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
                        if target not in self.results['hosts']:
                            self.results['hosts'][target] = {
                                'ports': {},
                                'os_guess': network.os_fingerprint(target),
                                'first_seen': datetime.now().isoformat()
                            }
                        self.results['hosts'][target]['ports'][port] = service_info

                    print(f"  [+] SERVICE: {target}:{port} - {service_info['service']}")

                sock.close()

            except Exception as e:
                print(f"  [-] SCAN ERROR: {target}:{port} - {e}")

        return open_ports

    def assess_vulnerabilities(self):
        """Assess vulnerabilities across all discovered services"""
        print(f"[*] VULNERABILITY ASSESSMENT: Analyzing security findings")

        vulnerabilities = []
        for host, info in self.results['hosts'].items():
            if 'ports' in info:
                for port, service_info in info['ports'].items():
                    vulns = self._assess_service_vulnerabilities(host, port, service_info)
                    vulnerabilities.extend(vulns)

        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities

    def _assess_service_vulnerabilities(self, host, port, service_info):
        """Assess vulnerabilities for a specific service"""
        vulnerabilities = []
        service = service_info['service']
        risk_level = service_info['risk_level']

        # SSH Vulnerabilities
        if service == 'ssh' and risk_level == 'MEDIUM':
            vulnerabilities.append({
                'host': host,
                'port': port,
                'service': service,
                'risk': 'MEDIUM',
                'cve': 'CWE-327',
                'description': 'Dropbear SSH detected - Potential weak cryptographic algorithms',
                'impact': 'Possible cryptographic vulnerabilities',
                'remediation': 'Upgrade to OpenSSH latest version or ensure strong crypto configuration',
                'evidence': service_info.get('banner', '')
            })

        # Web Service Vulnerabilities
        if service in ['http', 'https']:
            security = service_info.get('security_assessment', {})
            headers = security.get('security_headers', {})

            if not headers.get('hsts', {}).get('present', False):
                vulnerabilities.append({
                    'host': host,
                    'port': port,
                    'service': service,
                    'risk': 'LOW',
                    'cve': 'CWE-319',
                    'description': 'Missing HSTS header',
                    'impact': 'Potential SSL stripping attacks',
                    'remediation': 'Implement Strict-Transport-Security header',
                    'evidence': 'HSTS header not present'
                })

        # Telnet Vulnerabilities
        if service == 'telnet':
            vulnerabilities.append({
                'host': host,
                'port': port,
                'service': service,
                'risk': 'HIGH',
                'cve': 'CWE-319',
                'description': 'Telnet service detected - Unencrypted communication',
                'impact': 'Credentials transmitted in clear text',
                'remediation': 'Disable telnet and use SSH instead',
                'evidence': 'Telnet service active'
            })

        return vulnerabilities