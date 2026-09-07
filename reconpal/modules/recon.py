"""Passive and low-noise reconnaissance: subdomains, technologies, endpoints."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from ..core.http import PoliteClient
from ..core.models import Asset, Confidence, Finding, ScanResult, Severity
from ..core.scope import host_of, valid_hostname

# Paths worth a look on almost any web target. Deliberately short: this is a
# recon aid, not a content-discovery bruteforcer. Point ffuf at it if you want
# a real wordlist run, and do that only when scope clearly allows it.
INTERESTING_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger.json",
    "/openapi.json",
    "/swagger-ui.html",
    "/graphql",
    "/api",
    "/api/v1",
    "/actuator",
    "/actuator/health",
    "/server-status",
    "/admin",
    "/login",
    "/debug",
    "/metrics",
    "/health",
    "/status",
    "/.DS_Store",
    "/backup.zip",
    "/config.json",
]

# Header/body signatures. Kept as data so adding a technology is a one-line edit.
TECH_SIGNATURES = {
    "server": {
        "nginx": "nginx",
        "apache": "Apache",
        "iis": "Microsoft-IIS",
        "uvicorn": "Uvicorn (Python ASGI)",
        "gunicorn": "Gunicorn (Python WSGI)",
        "cloudflare": "Cloudflare",
        "envoy": "Envoy proxy",
    },
    "x-powered-by": {
        "php": "PHP",
        "express": "Express (Node.js)",
        "asp.net": "ASP.NET",
        "next.js": "Next.js",
    },
}

BODY_SIGNATURES = {
    r"wp-content|wp-includes": "WordPress",
    r"__NEXT_DATA__": "Next.js",
    r"ng-version=": "Angular",
    r"data-reactroot|__REACT_DEVTOOLS": "React",
    r"csrfmiddlewaretoken": "Django",
    r"Laravel|laravel_session": "Laravel",
    r"__NUXT__": "Nuxt.js",
    r"streamlit": "Streamlit",
}

SENSITIVE_BODY_HINTS = {
    "/.env": (r"(?i)^\s*[A-Z_]{3,}\s*=", "Environment file appears to expose variables"),
    "/.git/HEAD": (r"(?i)ref:\s*refs/", "Git repository metadata is readable"),
    "/.DS_Store": (r"\x00\x00\x00\x01Bud1", "macOS directory index is exposed"),
}


async def passive_subdomains(
    client: PoliteClient, result: ScanResult, apex: str
) -> None:
    """Pull subdomains from Certificate Transparency logs.

    This is passive with respect to the target: crt.sh is queried, not the
    client's infrastructure. Nothing here touches the target at all.
    """
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        # crt.sh is third-party, so it bypasses the scope guard by design;
        # we use a bare client rather than the scoped one.
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as ct:
            resp = await ct.get(url, headers={"User-Agent": "ReconPal/1.0"})
        if resp.status_code != 200:
            result.errors.append(f"crt.sh returned HTTP {resp.status_code}")
            return
        entries = resp.json()
    except Exception as exc:  # network, JSON, or rate-limit trouble
        result.errors.append(f"crt.sh lookup failed: {type(exc).__name__}")
        return

    found: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(apex) and valid_hostname(name):
                found.add(name)

    for name in sorted(found):
        result.add_asset(Asset(kind="subdomain", value=name, source="crt.sh"))


async def fingerprint(client: PoliteClient, result: ScanResult, target: str) -> None:
    """Identify server software and frameworks from headers and body markers."""
    resp = await client.get(target)
    if resp is None:
        result.errors.append(f"could not reach {target} for fingerprinting")
        return

    detected: list[str] = []
    for header, table in TECH_SIGNATURES.items():
        value = resp.headers.get(header, "")
        for needle, label in table.items():
            if needle.lower() in value.lower():
                detected.append(label)
                result.add_asset(
                    Asset(kind="technology", value=label, detail=f"{header}: {value}",
                          source="headers")
                )

    body = resp.text[:200_000]
    for pattern, label in BODY_SIGNATURES.items():
        if re.search(pattern, body, re.I):
            detected.append(label)
            result.add_asset(
                Asset(kind="technology", value=label, source="body markers")
            )

    # A version-bearing Server header is not a vulnerability, but it is the
    # kind of thing a report should record.
    server = resp.headers.get("server", "")
    if re.search(r"\d+\.\d+", server):
        result.add(
            Finding(
                module="recon.fingerprint",
                title="Server header discloses a version string",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    f"The Server header reports {server!r}. Version disclosure does "
                    "not create a vulnerability on its own, but it narrows an "
                    "attacker's search for known issues."
                ),
                evidence={"header": "Server", "value": server},
                remediation="Suppress or generalise the Server response header.",
            )
        )


async def discover_endpoints(
    client: PoliteClient, result: ScanResult, target: str, paths: list[str] | None = None
) -> None:
    """Probe a short list of interesting paths and record what answers."""
    paths = paths or INTERESTING_PATHS

    async def probe(path: str) -> None:
        url = urljoin(target + "/", path.lstrip("/"))
        resp = await client.get(url)
        if resp is None or resp.status_code in (404, 410):
            return

        # Many hosts answer everything with 200 and a soft-404 body. Treat a
        # response that looks like the site's own error page as nothing found.
        if resp.status_code == 200 and _looks_like_soft_404(resp.text):
            return

        result.add_asset(
            Asset(
                kind="endpoint",
                value=url,
                detail=f"HTTP {resp.status_code} ({len(resp.content)} bytes)",
                source="path probe",
            )
        )

        hint = SENSITIVE_BODY_HINTS.get(path)
        if hint and resp.status_code == 200:
            pattern, description = hint
            if re.search(pattern, resp.text[:4000], re.M):
                result.add(
                    Finding(
                        module="recon.endpoints",
                        title=f"Sensitive file reachable: {path}",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        target=url,
                        summary=(
                            f"{description}. This was matched on response content, "
                            "not merely on a 200 status, but confirm manually before "
                            "reporting."
                        ),
                        evidence={
                            "status": resp.status_code,
                            "bytes": len(resp.content),
                            "excerpt": resp.text[:200],
                        },
                        remediation=(
                            "Block access to this path at the web server or remove "
                            "the file from the deployed artifact."
                        ),
                    )
                )
        elif resp.status_code in (200, 401, 403) and path in (
            "/actuator",
            "/actuator/health",
            "/metrics",
            "/debug",
            "/server-status",
        ):
            result.add(
                Finding(
                    module="recon.endpoints",
                    title=f"Operational endpoint exposed: {path}",
                    severity=Severity.LOW if resp.status_code != 200 else Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    target=url,
                    summary=(
                        f"{path} responded with HTTP {resp.status_code}. Management "
                        "and diagnostic endpoints often leak configuration or "
                        "internal topology when reachable from the internet."
                    ),
                    evidence={"status": resp.status_code, "bytes": len(resp.content)},
                    remediation="Restrict management endpoints to an internal network.",
                )
            )

    await client.gather([probe(p) for p in paths], concurrency=6)


def _looks_like_soft_404(body: str) -> bool:
    lowered = body[:2000].lower()
    markers = ("page not found", "404 not found", "does not exist", "no encontrado")
    return any(m in lowered for m in markers)
