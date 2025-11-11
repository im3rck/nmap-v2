#!/usr/bin/env python3
"""
ApexScan ASE Script: smtp-open-relay.py
Category: intrusive, exploit-check
Description: Test for SMTP open relay vulnerability
Author: ApexScan Team

Tests if an SMTP server accepts and relays mail from external addresses
to external addresses (open relay misconfiguration). This is a critical
security vulnerability that allows spammers to abuse the server.
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
    port = context.get('port', 25)

    try:
        # Test for open relay vulnerability
        result = test_open_relay(target, port)

        vulnerable = result.get('vulnerable', False)
        details = result.get('details', '')
        test_performed = result.get('test_performed', False)
        relay_tests = result.get('relay_tests', [])

        if not test_performed:
            return {
                "output": "Unable to test SMTP open relay (connection or greeting failed)",
                "success": False,
                "data": {
                    "vulnerable": False,
                    "test_performed": False
                },
                "error": details
            }

        # Build output message
        output_lines = [
            f"SMTP Open Relay Test Results:",
        ]

        if vulnerable:
            output_lines.append(f"  Status: ⚠️  VULNERABLE - OPEN RELAY DETECTED!")
            output_lines.append(f"\n🚨 CRITICAL VULNERABILITY!")
            output_lines.append(f"   The SMTP server accepts and relays mail from external sources.")
            output_lines.append(f"   This allows attackers to:")
            output_lines.append(f"   • Send spam/phishing emails using your server")
            output_lines.append(f"   • Bypass email authentication mechanisms")
            output_lines.append(f"   • Get your server IP blacklisted by anti-spam systems")
            output_lines.append(f"   • Abuse your bandwidth and resources")
            output_lines.append(f"\n   Relay Tests Performed:")
            for test in relay_tests:
                status = "✓ RELAYED" if test['relayed'] else "✗ REJECTED"
                output_lines.append(f"   • {test['description']}: {status}")
            output_lines.append(f"\n   Details: {details}")
            output_lines.append(f"\n   Remediation:")
            output_lines.append(f"   → Configure relay restrictions (only allow authenticated users)")
            output_lines.append(f"   → Restrict relay to specific IP ranges/subnets")
            output_lines.append(f"   → Require SMTP authentication (SMTP AUTH)")
            output_lines.append(f"   → Enable sender verification (SPF, DKIM)")
            output_lines.append(f"   → Monitor mail logs for abuse")
            security_level = "CRITICAL"
        else:
            output_lines.append(f"  Status: ✓ NOT VULNERABLE")
            output_lines.append(f"\n   The SMTP server correctly rejects relay attempts.")
            output_lines.append(f"\n   Relay Tests Performed:")
            for test in relay_tests:
                status = "✓ RELAYED" if test['relayed'] else "✗ REJECTED"
                output_lines.append(f"   • {test['description']}: {status}")
            output_lines.append(f"\n   Details: {details}")
            security_level = "SECURE"

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "vulnerable": vulnerable,
                "security_level": security_level,
                "test_performed": test_performed,
                "relay_tests": relay_tests,
                "details": details
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while testing SMTP open relay",
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
            "output": f"SMTP open relay test failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def test_open_relay(target, port):
    """
    Test for SMTP open relay vulnerability.

    An open relay accepts mail from any sender to any recipient, allowing
    spammers to abuse the server. We test by attempting to relay mail from
    external addresses to external addresses.

    Args:
        target: Target SMTP server IP
        port: SMTP port (usually 25, 587, 465)

    Returns:
        Dictionary with test results
    """
    try:
        # Connect to SMTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Receive welcome banner
        response = receive_smtp_response(sock)

        if not response.startswith('220'):
            return {
                'vulnerable': False,
                'test_performed': False,
                'details': 'No SMTP welcome banner received',
                'relay_tests': []
            }

        # Send EHLO/HELO
        sock.sendall(b'EHLO apexscan.test\r\n')
        response = receive_smtp_response(sock)

        if not (response.startswith('250') or response.startswith('220')):
            # Try HELO if EHLO fails
            sock.sendall(b'HELO apexscan.test\r\n')
            response = receive_smtp_response(sock)

        if not response.startswith('250'):
            return {
                'vulnerable': False,
                'test_performed': False,
                'details': 'EHLO/HELO command failed',
                'relay_tests': []
            }

        # Define relay test scenarios
        # Using example.com addresses (reserved for documentation per RFC 2606)
        relay_tests = [
            {
                'description': 'External to External',
                'mail_from': 'spammer@example.com',
                'rcpt_to': 'victim@example.org',
                'relayed': False
            },
            {
                'description': 'Null sender to External',
                'mail_from': '',
                'rcpt_to': 'victim@example.org',
                'relayed': False
            }
        ]

        vulnerable = False

        # Test 1: External sender to external recipient
        test_result = attempt_relay(
            sock,
            'spammer@example.com',
            'victim@example.org'
        )
        relay_tests[0]['relayed'] = test_result
        if test_result:
            vulnerable = True

        # Reset connection if needed
        sock.sendall(b'RSET\r\n')
        receive_smtp_response(sock)

        # Test 2: Null sender (bounce messages) to external recipient
        test_result = attempt_relay(
            sock,
            '',
            'victim@example.org'
        )
        relay_tests[1]['relayed'] = test_result
        if test_result:
            vulnerable = True

        # Clean up
        try:
            sock.sendall(b'QUIT\r\n')
            receive_smtp_response(sock)
            sock.close()
        except:
            pass

        # Determine details message
        if vulnerable:
            relayed_count = sum(1 for test in relay_tests if test['relayed'])
            details = f"Server accepted {relayed_count} of {len(relay_tests)} relay attempts"
        else:
            details = "Server correctly rejected all relay attempts"

        return {
            'vulnerable': vulnerable,
            'test_performed': True,
            'details': details,
            'relay_tests': relay_tests
        }

    except Exception as e:
        return {
            'vulnerable': False,
            'test_performed': False,
            'details': f'Test failed: {str(e)}',
            'relay_tests': []
        }


def attempt_relay(sock, mail_from, rcpt_to):
    """
    Attempt to relay a message through the SMTP server.

    Args:
        sock: Socket connection
        mail_from: Sender email address (or empty string for null sender)
        rcpt_to: Recipient email address

    Returns:
        Boolean indicating if relay was accepted
    """
    try:
        # Send MAIL FROM
        if mail_from:
            sock.sendall(f'MAIL FROM:<{mail_from}>\r\n'.encode())
        else:
            sock.sendall(b'MAIL FROM:<>\r\n')  # Null sender

        response = receive_smtp_response(sock)

        if not response.startswith('250'):
            # Server rejected sender
            return False

        # Send RCPT TO
        sock.sendall(f'RCPT TO:<{rcpt_to}>\r\n'.encode())
        response = receive_smtp_response(sock)

        if response.startswith('250'):
            # Server accepted recipient - RELAY ALLOWED!
            # We don't actually send the message (no DATA command)
            return True
        else:
            # Server rejected recipient - proper behavior
            return False

    except Exception as e:
        return False


def receive_smtp_response(sock, timeout=5):
    """
    Receive SMTP server response.

    Args:
        sock: Socket connection
        timeout: Timeout in seconds

    Returns:
        String response from SMTP server
    """
    sock.settimeout(timeout)
    response = b''

    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk

            # SMTP responses end with \r\n
            # Multi-line responses have format: XXX-... followed by XXX ...
            if b'\r\n' in response:
                # Check if this is end of response (space after code, not dash)
                lines = response.split(b'\r\n')
                for line in lines:
                    if len(line) >= 4 and line[3:4] == b' ':
                        return response.decode('utf-8', errors='ignore')

            # Safety: don't read forever
            if len(response) > 10000:
                break

    except socket.timeout:
        pass

    return response.decode('utf-8', errors='ignore')
