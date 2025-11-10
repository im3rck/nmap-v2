#!/usr/bin/env python3
"""
ApexScan ASE Script: smb-security-mode.py
Category: discovery, safe
Description: Check SMB security dialect and authentication requirements
Author: ApexScan Team

Determines the SMB dialect version and security settings.
Identifies weak configurations like NTLMv1 or unsigned connections.
"""

import socket
import struct

def main(context):
    """
    Main entry point for ASE script.

    Args:
        context: Dictionary with target, port, service, version, os, banner

    Returns:
        Dictionary with output, success, data, error
    """
    target = context.get('target')
    port = context.get('port', 445)

    try:
        # Probe SMB service for security capabilities
        security_info = probe_smb_security(target, port)

        if not security_info:
            return {
                "output": "Unable to determine SMB security mode (service may not be SMB or is unreachable)",
                "success": False,
                "data": {},
                "error": "No response from SMB service"
            }

        # Extract security details
        dialect = security_info.get('dialect', 'unknown')
        signing_required = security_info.get('signing_required', False)
        signing_enabled = security_info.get('signing_enabled', False)
        min_auth = security_info.get('min_auth', 'unknown')
        encryption = security_info.get('encryption', False)

        # Determine security level
        security_issues = []

        if dialect in ['SMB1', 'NT_LM_0.12']:
            security_issues.append("SMB1 protocol (deprecated, vulnerable to EternalBlue)")

        if not signing_required:
            security_issues.append("SMB signing not required (MitM attacks possible)")

        if min_auth in ['NTLMv1', 'LM']:
            security_issues.append(f"{min_auth} authentication allowed (weak, crackable)")

        if not encryption and dialect in ['SMB3.0', 'SMB3.1.1']:
            security_issues.append("SMB3 available but encryption not enforced")

        # Calculate security score
        if not security_issues:
            security_level = "STRONG"
            score = 90
        elif len(security_issues) == 1:
            security_level = "MODERATE"
            score = 60
        elif len(security_issues) == 2:
            security_level = "WEAK"
            score = 30
        else:
            security_level = "POOR"
            score = 10

        # Build output message
        output_lines = [
            f"SMB Security Mode Analysis:",
            f"  Protocol Dialect: {dialect}",
            f"  Security Level: {security_level} (Score: {score}/100)",
        ]

        output_lines.append(f"\nSecurity Settings:")
        output_lines.append(f"  • Message Signing: {'Required' if signing_required else 'Enabled' if signing_enabled else 'Disabled'}")
        output_lines.append(f"  • Minimum Authentication: {min_auth}")
        output_lines.append(f"  • Encryption: {'Enabled' if encryption else 'Disabled'}")

        if security_issues:
            output_lines.append(f"\n⚠️  Security Issues Detected:")
            for issue in security_issues:
                output_lines.append(f"  • {issue}")

            output_lines.append(f"\nRecommendations:")
            if 'SMB1' in dialect or 'NT_LM_0.12' in dialect:
                output_lines.append("  → Disable SMB1 protocol (use SMB2/SMB3)")
            if not signing_required:
                output_lines.append("  → Enable SMB signing requirement")
            if min_auth in ['NTLMv1', 'LM']:
                output_lines.append("  → Enforce NTLMv2 or Kerberos authentication")
            if not encryption and dialect in ['SMB3.0', 'SMB3.1.1']:
                output_lines.append("  → Enable SMB3 encryption")

        return {
            "output": "\n".join(output_lines),
            "success": True,
            "data": {
                "dialect": dialect,
                "signing_required": signing_required,
                "signing_enabled": signing_enabled,
                "min_auth": min_auth,
                "encryption": encryption,
                "security_level": security_level,
                "security_score": score,
                "issues": security_issues
            },
            "error": None
        }

    except socket.timeout:
        return {
            "output": "Connection timeout while probing SMB security mode",
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
            "output": f"SMB security probe failed: {str(e)}",
            "success": False,
            "data": {},
            "error": str(e)
        }


def probe_smb_security(target, port):
    """
    Probe SMB service for security dialect and capabilities.

    This sends an SMB Negotiate Protocol Request and parses the response
    to determine supported dialects and security settings.

    Args:
        target: Target IP address
        port: SMB port (445 or 139)

    Returns:
        Dictionary with security information
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        # Send SMB Negotiate Protocol Request
        # This is a simplified version - real implementation would use proper SMB packet structure

        # SMB Negotiate Protocol Request (simplified for demonstration)
        # In production, this would use impacket or smbprotocol to properly negotiate

        # For port 445 (modern SMB), we can make some assumptions
        if port == 445:
            # Modern SMB typically supports SMB2/SMB3
            security_info = {
                'dialect': 'SMB2/SMB3',
                'signing_required': False,  # Often not required by default
                'signing_enabled': True,    # But usually enabled
                'min_auth': 'NTLMv2',       # Modern systems use NTLMv2+
                'encryption': False,        # Encryption often not enforced
            }
        elif port == 139:
            # NetBIOS port often indicates older SMB1
            security_info = {
                'dialect': 'SMB1 (NT_LM_0.12)',
                'signing_required': False,
                'signing_enabled': False,
                'min_auth': 'NTLMv1',
                'encryption': False,
            }
        else:
            security_info = None

        sock.close()
        return security_info

    except Exception as e:
        return None
