# Shadow Mapper Ultimate

### ULTIMATE SECURITY ASSESSMENT

Shadow Mapper Ultimate is a professional security scanner designed for comprehensive network reconnaissance, service enumeration, and vulnerability assessment. It systematically probes targets to discover live hosts, identify running services, and perform in-depth security analysis on discovered services like web and SSH.

## ✨ Features

- **Advanced Host Discovery**: Utilizes a multi-method approach (TCP, UDP, ICMP, HTTP) to accurately identify active hosts within a given network range.
- **Comprehensive Service Scanning**: Performs deep scans on discovered hosts to enumerate open ports and identify running services.
- **In-depth Web Service Analysis**:
    - Analyzes HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, etc.).
    - Detects underlying web technologies (e.g., Apache, Nginx, PHP, Node.js).
    - Checks for insecure configurations like lack of HTTPS redirection and directory listing.
- **SSH Security Assessment**:
    - Grabs SSH banners to identify server versions.
    - Checks for potentially weak configurations or outdated versions (e.g., older OpenSSH, Dropbear SSH).
- **Risk-Based Assessment**: Calculates a risk level for discovered services based on a variety of factors to help prioritize remediation efforts.
- **Concurrent Scanning**: Leverages a thread pool to perform scans concurrently, significantly speeding up the assessment process.
- **Flexible Reporting**: Prints a detailed report to the console and can export the full results to a JSON file for further analysis or integration.

## 🚀 Usage

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Scanner**:
    The tool requires a target, which can be a single IP, a CIDR range, a hyphenated range, or a file containing a list of targets.

    ```bash
    python3 main.py <target> [output_file]
    ```

    **Examples:**
    ```bash
    # Scan a CIDR range
    python3 main.py 192.168.1.0/24

    # Scan a range of IPs and save to a file
    python3 main.py 192.168.1.1-50 scan_results.json

    # Scan targets from a file
    python3 main.py targets.txt
    ```

## 🛠️ How It Works

The assessment is conducted in three main phases:

1.  **Phase 1: Host Discovery**: The tool first identifies all live hosts within the specified target scope. It uses a combination of TCP/UDP port checks, ICMP pings, and HTTP probes to ensure reliable discovery.

2.  **Phase 2: Service Enumeration**: For each active host, Shadow Mapper Ultimate performs a comprehensive scan of common ports. When a port is found to be open, it initiates a service-specific analysis.

3.  **Phase 3: Security Assessment**: The analyzer modules perform deep dives into specific services. For example, the `WebAnalyzer` checks for security best practices on web servers, while the `SSHAnalyzer` inspects SSH configuration. The findings are used to generate a list of vulnerabilities and calculate risk scores. Finally, a complete report is generated.

## 📁 Project Structure

```
shadow-mapper-ultimate/
├── README.md
├── requirements.txt
├── main.py                # Main entry point
├── config/                # Configuration files (settings, ports)
│   ├── settings.py
│   └── ports.py
├── core/                  # Core scanning and discovery logic
│   ├── scanner.py
│   ├── discovery.py
│   └── analyzer.py
├── modules/               # Service-specific analyzer modules
│   ├── web_analyzer.py
│   ├── ssh_analyzer.py
│   └── service_detector.py
├── utils/                 # Utility functions (network, reporting)
│   ├── network.py
│   ├── reporter.py
│   └── helpers.py
└── outputs/               # Default directory for scan reports
    └── .gitkeep
```
