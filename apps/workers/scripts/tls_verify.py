#!/usr/bin/env python3
"""
tls_verify.py – Strict certificate verification for DealBrief TLS scanning.

Usage:
    python3 tls_verify.py <host> [--port 443] [--json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import ssl
import socket
import sys
from typing import NoReturn, Dict, Any


class TLSVerificationError(RuntimeError):
    """Raised when any certificate validation step fails."""


def verify_host(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Establish a TLS connection with proper SNI and validate the certificate
    against the system trust store. Returns validation results.
    """
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = True          # CN / SAN must match `host`
    context.verify_mode = ssl.CERT_REQUIRED
    
    result = {
        'host': host,
        'port': port,
        'valid': False,
        'error': None,
        'certificate': None,
        'tls_version': None,
        'cipher_suite': None,
        'sni_supported': True,
        'validation_method': 'python_ssl_default_context'
    }

    try:
        with socket.create_connection((host, port), timeout=15) as tcp_sock:
            with context.wrap_socket(tcp_sock, server_hostname=host) as tls_sock:
                cert_dict = tls_sock.getpeercert()  # already validated by context
                cert_binary = tls_sock.getpeercert(binary_form=True)
                
                # Extract TLS connection details
                result['tls_version'] = tls_sock.version()
                result['cipher_suite'] = tls_sock.cipher()
                result['valid'] = True
                
                # Parse certificate details
                not_after_str = cert_dict.get("notAfter", "")
                not_before_str = cert_dict.get("notBefore", "")
                
                try:
                    not_after = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_before = dt.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    now = dt.datetime.utcnow()
                    
                    days_until_expiry = (not_after - now).days
                    is_expired = not_after <= now
                    is_not_yet_valid = not_before > now
                    
                except Exception as date_err:
                    days_until_expiry = None
                    is_expired = None
                    is_not_yet_valid = None
                
                # Extract subject and issuer details
                subject_dict = {}
                for field in cert_dict.get('subject', []):
                    if len(field) > 0 and len(field[0]) > 1:
                        subject_dict[field[0][0]] = field[0][1]
                
                issuer_dict = {}
                for field in cert_dict.get('issuer', []):
                    if len(field) > 0 and len(field[0]) > 1:
                        issuer_dict[field[0][0]] = field[0][1]
                
                # Extract SAN list
                sans = []
                for san_type, san_value in cert_dict.get("subjectAltName", []):
                    sans.append({'type': san_type, 'value': san_value})
                
                result['certificate'] = {
                    'subject': subject_dict,
                    'issuer': issuer_dict,
                    'subject_cn': subject_dict.get('commonName', ''),
                    'issuer_cn': issuer_dict.get('commonName', ''),
                    'not_before': not_before_str,
                    'not_after': not_after_str,
                    'days_until_expiry': days_until_expiry,
                    'is_expired': is_expired,
                    'is_not_yet_valid': is_not_yet_valid,
                    'serial_number': cert_dict.get('serialNumber', ''),
                    'version': cert_dict.get('version', 0),
                    'subject_alt_names': sans,
                    'self_signed': subject_dict.get('commonName') == issuer_dict.get('commonName')
                }
                
                # Additional validations
                if is_expired:
                    result['error'] = 'Certificate is expired'
                    result['valid'] = False
                elif is_not_yet_valid:
                    result['error'] = 'Certificate is not yet valid'
                    result['valid'] = False

    except ssl.SSLError as err:
        result['error'] = f"TLS handshake failed: {err}"
        result['sni_supported'] = 'SNI' not in str(err)
        
    except (socket.timeout, ConnectionRefusedError, OSError) as err:
        result['error'] = f"TCP connection to {host}:{port} failed: {err}"
        
    except Exception as err:
        result['error'] = f"Unexpected error: {err}"

    return result


def main(argv: list[str] | None = None) -> NoReturn:
    parser = argparse.ArgumentParser(description="Verify an HTTPS certificate with SNI")
    parser.add_argument("host", help="FQDN of the server (e.g. up.codes)")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default 443)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args(argv)

    result = verify_host(args.host, args.port)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result['valid']:
            print(f"✓ {args.host} – certificate chain and hostname verified")
            cert = result['certificate']
            if cert:
                print(f"  Subject CN : {cert['subject_cn']}")
                print(f"  Issuer CN  : {cert['issuer_cn']}")
                print(f"  Not After  : {cert['not_after']}")
                if cert['days_until_expiry'] is not None:
                    print(f"  Expires in : {cert['days_until_expiry']} days")
                sans = [san['value'] for san in cert['subject_alt_names']]
                print(f"  SAN list   : {', '.join(sans) or '—'}")
                print(f"  TLS Version: {result['tls_version']}")
        else:
            print(f"✗ {args.host} – {result['error']}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()