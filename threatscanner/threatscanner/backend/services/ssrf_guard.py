"""
SSRF Guard — validates URLs before any outbound request.
Blocks private/reserved IPs and dangerous schemes.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import HTTPException

BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS IMDS
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

ALLOWED_SCHEMES = {"http", "https"}


def validate_url_safe(url: str) -> str:
    """
    Raises HTTPException 400 if the URL is unsafe.
    Returns the validated URL on success.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, detail="Only http/https URLs are permitted")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(400, detail="URL has no valid hostname")

    # Reject raw IP literals that are private
    try:
        direct_ip = ipaddress.ip_address(hostname)
        _check_ip(direct_ip)
        return url
    except ValueError:
        pass  # hostname is a domain name — continue to DNS resolution

    # Resolve DNS and check every returned address
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(400, detail=f"Hostname '{hostname}' could not be resolved")

    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            _check_ip(ip_obj)
        except ValueError:
            pass  # malformed addr — skip

    return url


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    for blocked in BLOCKED_RANGES:
        if ip in blocked:
            raise HTTPException(
                400,
                detail=f"URL resolves to a private/reserved address ({ip}) — not permitted"
            )
