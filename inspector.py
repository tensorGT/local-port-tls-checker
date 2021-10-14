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
                    "cipher": cipher[0] if cipher else None,
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "not_after": not_after,
                    "warnings": warnings,
                }
    except ssl.SSLError as err:
        return {"tls_error": str(err)}
    except OSError:
        return None


async def scan_port(host: str, port: int, timeout: float = 1.5, check_tls: bool = True) -> Dict:
    result: Dict = {"port": port, "open": False}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        result["open"] = True
        try:
            banner_bytes = await asyncio.wait_for(reader.read(512), timeout=0.6)
            if banner_bytes:
                result["banner"] = banner_bytes.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
