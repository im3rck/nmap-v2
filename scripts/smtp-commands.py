#!/usr/bin/env python3
"""
ApexScan ASE Script: smtp-commands.py
Category: discovery, safe
Description: Enumerate supported SMTP commands
Author: ApexScan Team

Lists all SMTP commands supported by the mail server using HELP/EHLO.
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
    port = context.get('port', 25)

    try:
        # Enumerate SMTP commands
        smtp_info = enumerate_smtp_commands(target, port)

        if not smtp_info:
            return {
                "output": "Unable to enumerate SMTP commands (connection failed)",
                "success": False,
                "data": {},
                "error": "No SMTP response"
            }

        # Extract information
        banner = smtp_info.get('banner', 'Unknown')
        commands = smtp_info.get('commands', [])
        extensions = smtp_info.get('extensions', [])

        # Check for potentially dangerous commands
        dangerous_commands = []
        if 'VRFY' in commands:
            dangerous_commands.append('VRFY (user enumeration)')
        if 'EXPN' in commands:
            dangerous_commands.append('EXPN (mailing list expansion)')
        if 'ETRN' in commands:
            dangerous_commands.append('ETRN (extended turn - relay risk)')

        # Check for security features
        security_features = []
        if 'STARTTLS' in commands or 'STARTTLS' in extensions:
            security_features.append('STARTTLS (encryption available)')
        if 'AUTH' in commands or any('AUTH' in ext for ext in extensions):
            security_features.append('AUTH (authentication required)')

        # Determine security level
        if dangerous_commands and not security_features:
            security_level = "WEAK"
        elif dangerous_commands:
            security_level = "MODERATE"
        else:
            security_level = "NORMAL"

        # Build output
        output_lines = [
            f"SMTP Commands Enumeration:",
            f"  Server: {banner}",
            f"  Security Level: {security_level}",
        ]

        if commands:
            output_lines.append(f"\nSupported Commands ({len(commands)}):")
            for cmd in commands[:10]:
                marker = "⚠️ " if cmd in ['VRFY', 'EXPN', 'ETRN'] else "• "
                output_lines.append(f"  {marker}{cmd}")

        if extensions:
            output_lines.append(f"\nSMTP Extensions:")
            for ext in extensions[:5]:
                marker = "✓ " if 'AUTH' in ext or 'STARTTLS' in ext else "• "
                output_lines.append(f"  {marker}{ext}")

        if dangerous_commands:
            output_lines.append(f"\n⚠️  Potentially Dangerous Commands:")
            for cmd in dangerous_commands:
                output_lines.append(f"  • {cmd}")

            output_lines.append(f"\nRecommendations:")
            if 'VRFY' in commands:
                output_lines.append("  → Disable VRFY to prevent user enumeration")
            if 'EXPN' in commands:
                output_lines.append("  → Disable EXPN to prevent list expansion")
            if not security_features:
                output_lines.append("  → Enable STARTTLS for encryption")
                output_lines.append("  → Require authentication (SMTP AUTH)")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "banner": banner,
                "commands": commands,
                "extensions": extensions,
                "dangerous_commands": dangerous_commands,
                "security_features": security_features,
                "security_level": security_level
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while enumerating SMTP commands",
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
            "output": f"SMTP enumeration failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def enumerate_smtp_commands(target, port):
    """
    Enumerate SMTP commands using EHLO and HELP.

    Args:
        target: Target IP address
        port: SMTP port (usually 25, 587, 465)

    Returns:
        Dictionary with SMTP information
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Receive banner
        banner = receive_smtp_response(sock)

        if not banner.startswith('220'):
            sock.close()
            return None

        # Send EHLO command
        sock.sendall(b'EHLO apexscan\r\n')
        ehlo_response = receive_smtp_response(sock)

        # Parse EHLO response for extensions
        extensions = []
        commands = []

        if ehlo_response:
            for line in ehlo_response.split('\n'):
                line = line.strip()
                if line.startswith('250-') or line.startswith('250 '):
                    ext = line[4:].strip()
                    if ext and ext != banner and 'Hello' not in ext:
                        extensions.append(ext)
                        # Extract command name
                        cmd = ext.split()[0]
                        if cmd.isupper():
                            commands.append(cmd)

        # Try HELP command for additional commands
        sock.sendall(b'HELP\r\n')
        help_response = receive_smtp_response(sock)

        if help_response and help_response.startswith('214'):
            for line in help_response.split('\n'):
                # Extract command names from HELP response
                words = line.strip().split()
                for word in words:
                    if word.isupper() and len(word) <= 8 and word not in commands:
                        commands.append(word)

        # Standard SMTP commands if not already found
        standard_commands = ['HELO', 'EHLO', 'MAIL', 'RCPT', 'DATA', 'RSET', 'QUIT', 'NOOP']
        for cmd in standard_commands:
            if cmd not in commands:
                commands.append(cmd)

        # Clean up
        try:
            sock.sendall(b'QUIT\r\n')
        except:
            pass
        sock.close()

        return {
            'banner': banner.strip(),
            'commands': commands,
            'extensions': extensions
        }

    except Exception as e:
        return None


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
            if b'\r\n' in response:
                # Check if complete (space after code, not dash)
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
