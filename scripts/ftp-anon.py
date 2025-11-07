#!/usr/bin/env python3
"""
ApexScan Script: FTP Anonymous Login Check
Category: auth, safe
Description: Checks if FTP server allows anonymous login
Author: ApexScan Team
"""

import socket

def main(context):
    """Check for FTP anonymous login"""
    target = context.get('target')
    port = context.get('port', 21)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Receive FTP banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Try anonymous login
        sock.sendall(b"USER anonymous\r\n")
        user_response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        sock.sendall(b"PASS anonymous@\r\n")
        pass_response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        sock.close()
        
        # Check if login succeeded (230 code)
        if "230" in pass_response:
            return {
                'output': "Anonymous FTP login allowed! SECURITY RISK",
                'success': True,
                'data': {
                    'anonymous_login': True,
                    'banner': banner.strip(),
                    'severity': 'HIGH'
                },
                'error': None
            }
        else:
            return {
                'output': "Anonymous FTP login not allowed",
                'success': True,
                'data': {
                    'anonymous_login': False,
                    'banner': banner.strip()
                },
                'error': None
            }
            
    except Exception as e:
        return {
            'output': f"FTP check failed: {str(e)}",
            'success': False,
            'data': {},
            'error': str(e)
        }
