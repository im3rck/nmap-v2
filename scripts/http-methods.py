#!/usr/bin/env python3
"""
ApexScan ASE Script: http-methods.py
Category: discovery, safe
Description: Enumerates HTTP methods using OPTIONS request
Author: ApexScan Team

Performs an HTTP OPTIONS request to enumerate supported HTTP methods.
Identifies potentially dangerous methods (PUT, DELETE, TRACE, CONNECT).
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

        # Send OPTIONS request
        request = f"OPTIONS / HTTP/1.1\r\nHost: {target}\r\n\r\n"
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
                break

        sock.close()

        # Decode response
        response_str = response.decode('utf-8', errors='ignore')

        # Parse Allow header
        methods = []
        for line in response_str.split('\r\n'):
            if line.lower().startswith('allow:'):
                methods_str = line.split(':', 1)[1].strip()
                methods = [m.strip() for m in methods_str.split(',')]
                break

        if not methods:
            return {
                "output": "No Allow header found in OPTIONS response",
                "success": True,
                "data": {
                    "methods": [],
                    "dangerous_methods": []
                },
                "error": None
            }

        # Identify dangerous methods
        dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        dangerous_found = [m for m in methods if m.upper() in dangerous]

        # Build output message
        output_lines = [
            f"Supported HTTP methods: {', '.join(methods)}",
        ]

        if dangerous_found:
            output_lines.append(f"⚠️  DANGEROUS methods detected: {', '.join(dangerous_found)}")
            output_lines.append("   These methods may allow unauthorized file uploads or information disclosure.")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "methods": methods,
                "dangerous_methods": dangerous_found
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while sending OPTIONS request",
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
