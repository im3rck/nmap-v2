#!/usr/bin/env python3
"""
ApexScan ASE Script: ftp-bounce.py
Category: intrusive, exploit-check
Description: Check for FTP bounce attack vulnerability (PORT command abuse)
Author: ApexScan Team

Tests if an FTP server allows the PORT command to be used for scanning
or attacking third-party hosts (FTP bounce attack - CVE-1999-0017).

This is a historical vulnerability rarely seen in modern FTP servers,
but still worth checking for legacy systems.
"""

import socket
import time

def main(context):
    """
    Main entry point for ASE script.

    Args:
        context: Dictionary with target, port, service, version, os, banner

    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 21)

    try:
        # Test for FTP bounce vulnerability
        result = test_ftp_bounce(target, port)

        vulnerable = result.get('vulnerable', False)
        details = result.get('details', '')
        test_performed = result.get('test_performed', False)

        if not test_performed:
            return {
                "output": "Unable to test FTP bounce (connection or authentication failed)",
                "success": False,
                "data": {
                    "vulnerable": False,
                    "test_performed": False
                },
                "error": details
            }

        # Build output message
        output_lines = [
            f"FTP Bounce Attack Test Results:",
        ]

        if vulnerable:
            output_lines.append(f"  Status: ⚠️  VULNERABLE")
            output_lines.append(f"\n🚨 CRITICAL VULNERABILITY DETECTED!")
            output_lines.append(f"   The FTP server accepts PORT commands to third-party hosts.")
            output_lines.append(f"   This allows attackers to:")
            output_lines.append(f"   • Scan internal networks using the FTP server as a proxy")
            output_lines.append(f"   • Bypass firewall rules")
            output_lines.append(f"   • Launch attacks appearing to originate from the FTP server")
            output_lines.append(f"\n   Details: {details}")
            output_lines.append(f"\n   Remediation:")
            output_lines.append(f"   → Disable FTP PORT command or restrict to same-subnet")
            output_lines.append(f"   → Use PASV (passive) mode only")
            output_lines.append(f"   → Consider replacing FTP with SFTP/FTPS")
            security_level = "CRITICAL"
        else:
            output_lines.append(f"  Status: ✓ NOT VULNERABLE")
            output_lines.append(f"\n   The FTP server correctly rejects PORT commands to third-party hosts.")
            output_lines.append(f"   Details: {details}")
            security_level = "SECURE"

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "vulnerable": vulnerable,
                "security_level": security_level,
                "test_performed": test_performed,
                "details": details,
                "cveid": "CVE-1999-0017" if vulnerable else None
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while testing FTP bounce",
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
            "output": f"FTP bounce test failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def test_ftp_bounce(target, port):
    """
    Test for FTP bounce vulnerability using PORT command.

    The FTP bounce attack works by abusing the PORT command to make
    the FTP server connect to arbitrary hosts/ports on behalf of the attacker.

    Args:
        target: Target FTP server IP
        port: FTP port (usually 21)

    Returns:
        Dictionary with test results
    """
    try:
        # Connect to FTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Receive welcome banner
        response = receive_ftp_response(sock)

        if not response.startswith('220'):
            return {
                'vulnerable': False,
                'test_performed': False,
                'details': 'No FTP welcome banner received'
            }

        # Try anonymous login
        sock.sendall(b'USER anonymous\r\n')
        response = receive_ftp_response(sock)

        if response.startswith('331'):  # Username OK, need password
            sock.sendall(b'PASS anonymous@example.com\r\n')
            response = receive_ftp_response(sock)

        if not (response.startswith('230') or response.startswith('530')):
            # If not logged in and not auth failure, something else went wrong
            return {
                'vulnerable': False,
                'test_performed': False,
                'details': 'Unexpected response during login'
            }

        # Even if login failed, try PORT command
        # Some servers might allow PORT before authentication

        # Test PORT command with a third-party IP (RFC1918 private IP)
        # Format: PORT h1,h2,h3,h4,p1,p2 where IP=h1.h2.h3.h4 and port=(p1*256)+p2
        # Using 10.0.0.1:80 (port 80 = 0*256 + 80)
        test_ip = '10,0,0,1'
        test_port_high = 0
        test_port_low = 80

        port_command = f'PORT {test_ip},{test_port_high},{test_port_low}\r\n'
        sock.sendall(port_command.encode())

        response = receive_ftp_response(sock)

        # Check if server accepted the PORT command
        if response.startswith('200'):
            # Server accepted PORT to third-party IP - VULNERABLE
            vulnerable = True
            details = f'Server accepted PORT command to 10.0.0.1:80 (Response: {response.strip()})'

            # Try to actually trigger the connection with a LIST or NLST command
            sock.sendall(b'LIST\r\n')
            list_response = receive_ftp_response(sock)

            if list_response.startswith('150') or list_response.startswith('125'):
                details += ' - Server attempted data connection to third-party host'

        elif response.startswith('500') or response.startswith('501') or response.startswith('421'):
            # Server rejected PORT command - likely NOT VULNERABLE
            vulnerable = False
            details = f'Server rejected PORT command to third-party IP (Response: {response.strip()})'

        elif response.startswith('530'):
            # Not logged in - might still be vulnerable but can't test fully
            vulnerable = False
            details = 'Authentication required before PORT command - unable to test bounce fully'

        else:
            vulnerable = False
            details = f'Unexpected response to PORT command: {response.strip()}'

        # Clean up
        try:
            sock.sendall(b'QUIT\r\n')
            sock.close()
        except:
            pass

        return {
            'vulnerable': vulnerable,
            'test_performed': True,
            'details': details
        }

    except Exception as e:
        return {
            'vulnerable': False,
            'test_performed': False,
            'details': f'Test failed: {str(e)}'
        }


def receive_ftp_response(sock, timeout=5):
    """
    Receive FTP server response.

    Args:
        sock: Socket connection
        timeout: Timeout in seconds

    Returns:
        String response from FTP server
    """
    sock.settimeout(timeout)
    response = b''

    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk

            # FTP responses end with \r\n
            # Multi-line responses have format: XXX-... followed by XXX ...
            if b'\r\n' in response:
                # Check if this is end of response
                lines = response.split(b'\r\n')
                if len(lines) >= 2 and lines[-2]:
                    last_line = lines[-2].decode('utf-8', errors='ignore')
                    # Check if it's a complete response (starts with 3-digit code and space)
                    if len(last_line) >= 4 and last_line[3] == ' ':
                        break

            # Safety: don't read forever
            if len(response) > 10000:
                break

    except socket.timeout:
        pass

    return response.decode('utf-8', errors='ignore')
