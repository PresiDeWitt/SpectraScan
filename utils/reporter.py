#!/usr/bin/env python3
"""
Reporting and output utilities
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    def __init__(self):
        pass

    def generate_executive_summary(self, results, live_hosts, vulnerabilities, scan_duration):
        """Generate executive summary"""
        total_hosts = len(live_hosts)
        total_services = sum(len(host.get('ports', {})) for host in results['hosts'].values())
        total_vulns = len(vulnerabilities)

        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            risk_counts[vuln['risk']] += 1

        results['network_summary'] = {
            'total_hosts': total_hosts,
            'total_services': total_services,
            'total_vulnerabilities': total_vulns,
            'risk_breakdown': risk_counts,
            'scan_duration': scan_duration,
            'recommendation_priority': 'HIGH' if risk_counts['HIGH'] > 0 else 'MEDIUM' if risk_counts[
                                                                                              'MEDIUM'] > 0 else 'LOW'
        }

    def print_final_report(self, results, vulnerabilities):
        """Print final comprehensive report"""
        summary = results['network_summary']

        print("\n" + "=" * 80)
        print("SHADOW MAPPER ULTIMATE - SECURITY ASSESSMENT REPORT")
        print("=" * 80)

        print(f"\n[+] EXECUTIVE SUMMARY")
        print(f"    Network Scope: {summary['total_hosts']} active hosts")
        print(f"    Services Found: {summary['total_services']} services")
        print(f"    Vulnerabilities: {summary['total_vulnerabilities']} issues")
        print(f"    Risk Priority: {summary['recommendation_priority']}")

        print(f"\n[+] RISK BREAKDOWN")
        for risk, count in summary['risk_breakdown'].items():
            print(f"    {risk}: {count} vulnerabilities")

        print(f"\n[+] DETAILED FINDINGS")
        for host, info in results['hosts'].items():
            print(f"\n    [+] HOST: {host}")
            if info.get('os_guess'):
                print(f"        OS: {info['os_guess']}")

            if 'ports' in info and info['ports']:
                for port, service in info['ports'].items():
                    print(f"        [+] {port}/tcp - {service['service']} [{service['risk_level']}]")

        if vulnerabilities:
            print(f"\n[!] SECURITY VULNERABILITIES")
            for vuln in vulnerabilities:
                print(f"\n    [!] {vuln['risk']} - {vuln['service'].upper()} on {vuln['host']}:{vuln['port']}")
                print(f"        Description: {vuln['description']}")
                print(f"        Remediation: {vuln['remediation']}")

    def export_report(self, results, output_file=None):
        """Export comprehensive report"""
        if not output_file:
            output_file = f"security_scan_{results['scan_metadata']['timestamp']}.json"

        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)

            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[+] REPORT EXPORTED: Comprehensive report saved: {output_file}")
            return output_file
        except Exception as e:
            print(f"[-] EXPORT ERROR: Failed to save report: {e}")
            return None