#!/usr/bin/env python3
"""
Web service analysis module
"""

import requests
from utils.helpers import calculate_risk_level

class WebAnalyzer:
    def __init__(self):
        pass

    def analyze_web_service(self, target, port):
        """Comprehensive web service analysis"""
        web_info = {}
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{target}:{port}"

            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)

            web_info['banner'] = f"HTTP {response.status_code}"
            web_info['security_assessment'] = {
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'security_headers': self.analyze_security_headers(response.headers),
                'https_redirect': self.check_https_redirect(target, port),
                'directory_listing': self.check_directory_listing(target, port)
            }

            web_info['technologies'] = self.detect_web_tech(response)

            risk_factors = []
            if web_info['security_assessment']['server'] == 'Unknown':
                risk_factors.append('unknown_server')
            if not web_info['security_assessment']['https_redirect'] and port == 80:
                risk_factors.append('no_https_redirect')

            web_info['risk_level'] = calculate_risk_level(risk_factors)

        except Exception as e:
            web_info['banner'] = f"Web analysis failed: {str(e)}"

        return web_info

    def analyze_security_headers(self, headers):
        """Analyze security headers"""
        security_headers = {}
        important_headers = {
            'Strict-Transport-Security': 'hsts',
            'Content-Security-Policy': 'csp',
            'X-Frame-Options': 'frame_options',
            'X-Content-Type-Options': 'content_type',
            'X-XSS-Protection': 'xss_protection',
            'Referrer-Policy': 'referrer_policy'
        }

        for header, key in important_headers.items():
            security_headers[key] = {
                'present': header in headers,
                'value': headers.get(header, 'MISSING')
            }

        return security_headers

    def detect_web_tech(self, response):
        """Detect web technologies"""
        tech = []
        server = response.headers.get('Server', '').lower()

        if 'apache' in server:
            tech.append('Apache')
        elif 'nginx' in server:
            tech.append('Nginx')
        elif 'iis' in server:
            tech.append('IIS')
        elif 'micro_httpd' in server:
            tech.append('Micro_httpd')

        powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            tech.append('PHP')
        elif 'asp.net' in powered_by:
            tech.append('ASP.NET')
        elif 'express' in powered_by:
            tech.append('Node.js')

        return tech

    def check_https_redirect(self, target, port):
        """Check HTTP to HTTPS redirect"""
        if port == 80:
            try:
                response = requests.get(f"http://{target}", timeout=3, verify=False, allow_redirects=False)
                return response.status_code in [301, 302] and 'https' in response.headers.get('Location', '')
            except:
                pass
        return False

    def check_directory_listing(self, target, port):
        """Check for directory listing vulnerability"""
        try:
            response = requests.get(f"http://{target}:{port}/", timeout=3, verify=False)
            return '<title>Index of' in response.text
        except:
            return False