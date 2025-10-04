#!/usr/bin/env python3
"""
[SHADOW MAPPER ULTIMATE] - Main Entry Point
"""

import time
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from core.scanner import NetworkScanner
from core.discovery import HostDiscovery
from utils import network, helpers, reporter
from config import settings


def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Shadow Mapper Ultimate v3.1 - Professional Security Scanner")
        print("Usage: python3 main.py <target> [output_file]")
        print("\nExamples:")
        print("  python3 main.py 192.168.1.0/24")
        print("  python3 main.py 192.168.1.1-50 scan_results.json")
        print("  python3 main.py targets.txt")
        return

    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Initialize components
    scanner = NetworkScanner()
    discovery = HostDiscovery()
    report_gen = reporter.ReportGenerator()

    # Set scan metadata
    scanner.results['scan_metadata']['timestamp'] = datetime.now().isoformat()
    scanner.results['scan_metadata']['scan_id'] = helpers.generate_scan_id()

    print(f"[*] SHADOW MAPPER ULTIMATE: Initializing security assessment")
    print(f"[*] TARGET: {target}")
    print(f"[*] TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start_time = time.time()

    # Phase 1: Host Discovery
    print(f"\n[*] PHASE 1: Advanced host discovery")
    targets = network.validate_target(target)
    if not targets:
        print("[-] ERROR: No valid targets found")
        return

    print(f"[*] SCOPE: {len(targets)} targets identified")

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        list(executor.map(discovery.advanced_host_discovery, targets))

    print(f"[+] DISCOVERY: {len(discovery.live_hosts)} active hosts found")

    # Phase 2: Service Scanning
    if discovery.live_hosts:
        print(f"\n[*] PHASE 2: Comprehensive service enumeration")

        # Transfer host information from discovery to scanner
        for host in discovery.live_hosts:
            host_info = discovery.get_host_info(host)
            if host not in scanner.results['hosts']:
                scanner.results['hosts'][host] = {
                    'ports': {},
                    'os_guess': host_info.get('os_guess', 'Unknown'),
                    'discovery_methods': host_info.get('discovery_methods', []),
                    'first_seen': host_info.get('first_seen', datetime.now().isoformat())
                }

        # Perform service scanning
        for host in discovery.live_hosts:
            scanner.comprehensive_service_scan(host)

    # Phase 3: Vulnerability Assessment
    print(f"\n[*] PHASE 3: Security vulnerability assessment")
    vulnerabilities = scanner.assess_vulnerabilities()
    report_gen.generate_executive_summary(
        scanner.results,
        discovery.live_hosts,
        vulnerabilities,
        time.time() - start_time
    )

    # Finalization
    scan_duration = time.time() - start_time
    print(f"\n[+] COMPLETE: Security assessment finished in {scan_duration:.2f}s")

    # Reports
    report_gen.print_final_report(scanner.results, vulnerabilities)
    if output_file:
        report_gen.export_report(scanner.results, output_file)


if __name__ == "__main__":
    try:
        import dns.resolver
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError as e:
        print(f"[-] ERROR: Missing dependencies: {e}")
        print("Install: pip install dnspython requests")
        sys.exit(1)

    print("""
    ╔═╗┌─┐┌┬┐┌─┐┌┐┌┌┬┐  ┌┬┐┌─┐┌─┐┌┐┌┌─┐┌─┐  ┌─┐┌┬┐┌─┐┌─┐┌┬┐┬ ┬┌─┐
    ╠═╝├─┤ │ ├─┤│││ ││  ││││ ││ ││││├┤ └─┐  │ │ ││├┤ ├─┤ │ │ │└─┐
    ╩  ┴ ┴ ┴ ┴ ┴┘└┘─┴┘  ┴ ┴└─┘└─┘┘└┘└─┘└─┘  └─┘─┴┘└─┘┴ ┴ ┴ └─┘└─┘
                   ULTIMATE SECURITY ASSESSMENT
    """)

    main()