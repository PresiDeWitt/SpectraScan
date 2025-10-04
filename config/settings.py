#!/usr/bin/env python3
"""
Configuration settings for Shadow Mapper Ultimate
"""

# Scanner configuration
SCANNER_VERSION = "3.1"
DEFAULT_TIMEOUT = 2
MAX_WORKERS = 20
SCAN_DELAY = 0.1  # seconds between scans

# Risk levels
RISK_LEVELS = {
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
}

# Output settings
REPORT_INDENT = 2
DEFAULT_OUTPUT_DIR = "outputs"