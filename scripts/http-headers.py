#!/usr/bin/env python3
"""
ApexScan ASE Script: http-headers.py
Category: discovery, safe
Description: Analyzes HTTP security headers
Author: ApexScan Team

Analyzes HTTP security headers to assess security posture.
Identifies missing security headers and potential vulnerabilities.
"""

import socket

def main(context):
    """
    Main entry point for ASE script.

    Args:
        context: Dictionary with target, port, service, version, os, banner

    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 80)

    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        # Send GET request
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        # Receive response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Check if we've received the headers
            if b"\r\n\r\n" in response:
                # Just get headers for this analysis
                break

        sock.close()

        # Decode response
        response_str = response.decode('utf-8', errors='ignore')

        # Parse headers
        headers = {}
        lines = response_str.split('\r\n')
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        # Security headers to check
        security_headers = {
            'strict-transport-security': 'HSTS - Enforces HTTPS connections',
            'x-frame-options': 'Clickjacking protection',
            'x-content-type-options': 'MIME-sniffing protection',
            'content-security-policy': 'XSS and injection attack mitigation',
            'x-xss-protection': 'XSS filter',
            'referrer-policy': 'Controls referrer information',
            'permissions-policy': 'Feature policy controls',
        }

        # Analyze headers
        found_headers = []
        missing_headers = []

        for header, description in security_headers.items():
            if header in headers:
                found_headers.append({
                    "header": header,
                    "value": headers[header],
                    "description": description
                })
            else:
                missing_headers.append({
                    "header": header,
                    "description": description
                })

        # Check for information disclosure
        disclosure_headers = []
        disclosure_check = {
            'server': 'Server version disclosure',
            'x-powered-by': 'Technology stack disclosure',
            'x-aspnet-version': 'ASP.NET version disclosure',
        }

        for header, description in disclosure_check.items():
            if header in headers:
                disclosure_headers.append({
                    "header": header,
                    "value": headers[header],
                    "risk": description
                })

        # Calculate security score
        total_security_headers = len(security_headers)
        found_count = len(found_headers)
        security_score = (found_count / total_security_headers) * 100

        # Determine security level
        if security_score >= 80:
            security_level = "Strong"
        elif security_score >= 50:
            security_level = "Moderate"
        elif security_score >= 30:
            security_level = "Weak"
        else:
            security_level = "Poor"

        # Build output message
        output_lines = [
            f"Security Headers Analysis:",
            f"  Security Score: {security_score:.0f}% ({security_level})",
            f"  Found: {found_count}/{total_security_headers} security headers",
        ]

        if found_headers:
            output_lines.append("\nPresent Security Headers:")
            for h in found_headers:
                val_display = h['value'][:50] + "..." if len(h['value']) > 50 else h['value']
                output_lines.append(f"  ✓ {h['header']}: {val_display}")

        if missing_headers:
            output_lines.append("\n⚠️  Missing Security Headers:")
            for h in missing_headers:
                output_lines.append(f"  ✗ {h['header']} - {h['description']}")

        if disclosure_headers:
            output_lines.append("\n⚠️  Information Disclosure:")
            for h in disclosure_headers:
                output_lines.append(f"  ! {h['header']}: {h['value']} ({h['risk']})")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "security_score": security_score,
                "security_level": security_level,
                "found_headers": found_headers,
                "missing_headers": missing_headers,
                "disclosure_headers": disclosure_headers
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while analyzing headers",
            "success": False,
            "data": {},
            "error": "Timeout"
        }
    except ConnectionRefusedError:
        return {
            "output": f"Connection refused to {target}:{port}",
            "success": False,
            "data": {},
            "error": "Connection refused"
        }
    except Exception as e:
        return {
            "output": f"Error: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }
