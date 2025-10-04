#!/usr/bin/env python3
"""
Helper functions and utilities
"""

import time
import os
from datetime import datetime

def generate_scan_id():
    """Generate unique scan ID"""
    return f"SCAN-{int(time.time())}-{os.urandom(4).hex()}"

def calculate_risk_level(risk_factors):
    """Calculate risk level based on factors"""
    if any(factor in risk_factors for factor in ['dropbear_ssh', 'old_openssh']):
        return 'MEDIUM'
    elif risk_factors:
        return 'LOW'
    return 'INFO'

def check_https_redirect(target, port):
    """Check HTTP to HTTPS redirect"""
    if port == 80:
        try:
            import requests
            response = requests.get(f"http://{target}", timeout=3, verify=False, allow_redirects=False)
            return response.status_code in [301, 302] and 'https' in response.headers.get('Location', '')
        except:
            pass
    return False

def check_directory_listing(target, port):
    """Check for directory listing vulnerability"""
    try:
        import requests
        response = requests.get(f"http://{target}:{port}/", timeout=3, verify=False)
        return '<title>Index of' in response.text
    except:
        return False