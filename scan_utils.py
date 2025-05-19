# scan_utils.py

import requests
import socket
from urllib.parse import urlparse

def perform_scan(url):
    scan_data = {
        "url": url,
        "status": "Failed",
        "issues": [],
        "open_ports": []
    }

    try:
        # 1. Check if URL is reachable
        response = requests.get(url, timeout=5)
        scan_data["status"] = f"{response.status_code} OK"

        # 2. Check for basic security headers
        required_headers = [
            "Content-Security-Policy", 
            "Strict-Transport-Security", 
            "X-Content-Type-Options", 
            "X-Frame-Options", 
            "X-XSS-Protection"
        ]
        for header in required_headers:
            if header not in response.headers:
                scan_data["issues"].append(f"Missing header: {header}")

        # 3. Port scan for 80 and 443
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        ports = [80, 443]
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=2):
                    scan_data["open_ports"].append(port)
            except Exception:
                pass

    except Exception as e:
        scan_data["error"] = str(e)

    return scan_data
