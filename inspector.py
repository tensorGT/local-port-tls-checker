import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_allowed_target(host: str, extra_allowlist: List[str]) -> bool:
    if host in extra_allowlist:
        return True
    try:
        resolved = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved)
        return any(ip_obj in net for net in ALLOWED_NETWORKS)
    except OSError:
        return False


def inspect_tls(host: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
                warnings: List[str] = []
                if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    warnings.append("weak TLS version: %s" % proto)
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    if days_left < 30:
                        warnings.append("cert expiring soon (%d days)" % days_left)
                return {
                    "protocol": proto,
