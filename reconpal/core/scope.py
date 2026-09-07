"""Scope control.

Every scanner eventually points at something it should not have. This module
makes the in-scope set explicit and refuses anything outside it, so an
overly broad wordlist or a wandering redirect cannot quietly widen the
engagement.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Ranges that are almost never a legitimate bug-bounty target and are a common
# way to accidentally hit infrastructure that is not the client's.
_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


class ScopeError(Exception):
    """Raised when a request would leave the authorised scope."""


@dataclass
class Scope:
    """The set of hosts this run is permitted to touch.

    `allow` entries may be exact hosts ("api.example.com") or wildcards
    ("*.example.com"). A bare apex also matches its subdomains, which is how
    most programs actually word their scope tables.
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow_private: bool = False

    @classmethod
    def from_target(cls, target: str, include_subdomains: bool = True) -> "Scope":
        host = host_of(target)
        allow = [host]
        if include_subdomains and not host.replace(".", "").isdigit():
            allow.append(f"*.{host}")
        return cls(allow=allow)

    def _matches(self, host: str, pattern: str) -> bool:
        host = host.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)
        return host == pattern

    def permits(self, url_or_host: str) -> bool:
        try:
            host = host_of(url_or_host)
        except ValueError:
            return False
        if any(self._matches(host, p) for p in self.deny):
            return False
        return any(self._matches(host, p) for p in self.allow)

    def check(self, url_or_host: str) -> None:
        """Raise if the target is out of scope. Call before every request."""
        host = host_of(url_or_host)
        if not self.permits(url_or_host):
            raise ScopeError(
                f"{host} is not in the authorised scope "
                f"(allowed: {', '.join(self.allow) or 'nothing'})"
            )
        if not self.allow_private and _resolves_private(host):
            raise ScopeError(
                f"{host} resolves to a private or loopback address; "
                f"pass --allow-private only if that is genuinely your target"
            )

    def describe(self) -> str:
        parts = [f"allow: {', '.join(self.allow)}"]
        if self.deny:
            parts.append(f"deny: {', '.join(self.deny)}")
        if self.allow_private:
            parts.append("private ranges permitted")
        return " | ".join(parts)


def host_of(url_or_host: str) -> str:
    """Extract a bare hostname from a URL or a host string."""
    value = (url_or_host or "").strip()
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        raise ValueError(f"could not parse a hostname from {url_or_host!r}")
    return host.lower()


def normalise_target(target: str) -> str:
    """Return a canonical https:// origin for a user-supplied target."""
    value = (target or "").strip().rstrip("/")
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError(f"could not parse a hostname from {target!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _resolves_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETS):
            return True
    return False


_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def valid_hostname(host: str) -> bool:
    host = host.rstrip(".")
    if not host or len(host) > 253:
        return False
    return all(_LABEL.match(label) for label in host.split("."))
