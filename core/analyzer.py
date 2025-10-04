#!/usr/bin/env python3
"""
Service analysis core module
"""

from modules.web_analyzer import WebAnalyzer
from modules.ssh_analyzer import SSHAnalyzer
from utils import network

class ServiceAnalyzer:
    def __init__(self):
        self.web_analyzer = WebAnalyzer()
        self.ssh_analyzer = SSHAnalyzer()

    def analyze_service(self, target, port):
        """Deep service analysis with security checks"""
        service_info = {
            'service': network.guess_service(port),
            'state': 'open',
            'protocol': 'tcp',
            'banner': '',
            'security_assessment': {},
            'technologies': [],
            'risk_level': 'LOW'
        }

        try:
            if port in [80, 443, 8080, 8443, 8888]:
                service_info.update(self.web_analyzer.analyze_web_service(target, port))
            elif port == 22:
                service_info.update(self.ssh_analyzer.analyze_ssh_service(target, port))
            elif port == 21:
                service_info.update(self.analyze_ftp_service(target, port))
            elif port == 23:
                service_info.update(self.analyze_telnet_service(target, port))
            elif port == 445:
                service_info.update(self.analyze_smb_service(target, port))
            elif port == 3389:
                service_info.update(self.analyze_rdp_service(target, port))
            else:
                service_info.update(self.analyze_generic_service(target, port))

        except Exception as e:
            service_info['banner'] = f"Analysis error: {str(e)}"

        return service_info

    def analyze_ftp_service(self, target, port):
        return {'banner': 'FTP service detected', 'risk_level': 'LOW'}

    def analyze_telnet_service(self, target, port):
        return {'banner': 'Telnet service - UNENCRYPTED', 'risk_level': 'HIGH'}

    def analyze_smb_service(self, target, port):
        return {'banner': 'SMB service', 'risk_level': 'MEDIUM'}

    def analyze_rdp_service(self, target, port):
        return {'banner': 'RDP service', 'risk_level': 'MEDIUM'}

    def analyze_generic_service(self, target, port):
        return {'banner': 'Generic TCP service', 'risk_level': 'LOW'}