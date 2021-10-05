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
