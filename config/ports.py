#!/usr/bin/env python3
"""
Port configurations for network scanning
"""

# Common ports for comprehensive scanning
COMPREHENSIVE_PORTS = [
    # Servicios comunes
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
    445, 993, 995, 1723, 3306, 3389, 5432, 5900, 5985, 5986,
    # Servicios web
    8000, 8080, 8443, 8888, 9000, 9043, 9090, 10000,
    # Servicios de aplicación
    27017, 6379, 9200, 9300, 11211, 27017
]

# Ports for host discovery
DISCOVERY_PORTS_TCP = [22, 23, 80, 443, 445, 3389, 8080, 8443]
DISCOVERY_PORTS_UDP = [53, 67, 68, 123, 161, 500, 4500]

# Service mapping
SERVICE_MAP = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios', 143: 'imap',
    443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
    5985: 'winrm', 5986: 'winrm-ssl', 6379: 'redis', 8000: 'http-alt',
    8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt',
    9000: 'jenkins', 9043: 'websphere', 9090: 'websocket',
    10000: 'webmin', 11211: 'memcache', 27017: 'mongodb'
}