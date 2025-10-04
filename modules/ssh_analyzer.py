#!/usr/bin/env python3
"""
SSH service analysis module
"""

import socket
from utils.helpers import calculate_risk_level

class SSHAnalyzer:
    def __init__(self):
        pass

    def analyze_ssh_service(self, target, port):
        """SSH service security analysis"""
        ssh_info = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            ssh_info['banner'] = banner
            ssh_info['security_assessment'] = {
                'ssh_version': banner,
                'weak_algorithms': self.check_ssh_security(banner),
                'key_exchange': self.analyze_ssh_kex(banner)
            }

            risk_factors = []
            if 'dropbear' in banner.lower():
                risk_factors.append('dropbear_ssh')
            if 'openssh' in banner.lower() and any(ver in banner for ver in ['7.0', '7.1', '7.2']):
                risk_factors.append('old_openssh')

            ssh_info['risk_level'] = calculate_risk_level(risk_factors)

        except Exception as e:
            ssh_info['banner'] = f"SSH analysis failed: {str(e)}"

        return ssh_info

    def check_ssh_security(self, banner):
        """Check SSH security issues"""
        issues = []
        banner_lower = banner.lower()
        if 'dropbear' in banner_lower:
            issues.append('uses_dropbear')
        if 'openssh' in banner_lower and any(ver in banner for ver in ['7.0', '7.1', '7.2']):
            issues.append('old_version')
        return issues

    def analyze_ssh_kex(self, banner):
        """Analyze SSH key exchange (simplified)"""
        return 'unknown'