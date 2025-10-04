#!/usr/bin/env python3
"""
Network utility functions
"""

import socket
import ipaddress
from config import ports

def validate_target(target):
    """Validate and expand target range"""
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]

        elif '-' in target:
            start_ip, end_ip = target.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            return [str(ipaddress.ip_address(ip))
                    for ip in range(int(start), int(end) + 1)]

        elif os.path.isfile(target):
            with open(target, 'r') as f:
                return [line.strip() for line in f if line.strip()]

        else:
            return [socket.gethostbyname(target)]

    except Exception as e:
        print(f"[-] Target validation failed: {e}")
        return []

def os_fingerprint(target):
    """Basic OS fingerprinting via TTL"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, 80))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()

        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device"
    except:
        pass
    return "Unknown"

def guess_service(port):
    """Service identification by port number"""
    return ports.SERVICE_MAP.get(port, f'service-{port}')