"""Passive configuration audit: headers, CORS, cookies, and content leakage.

Everything here is read-only. No payloads, no state change, no authentication
bypass attempts. These checks are safe to run against production because they
observe how a server answers ordinary requests.
"""

from __future__ import annotations

import re

from ..core.http import PoliteClient
from ..core.models import Confidence, Finding, ScanResult, Severity

SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS is not set, so a downgrade to plaintext HTTP is not prevented for "
        "clients that have not previously pinned the host.",
        "Set Strict-Transport-Security with a max-age of at least 31536000.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy. CSP is the main defence-in-depth control "
        "limiting the impact of an injected script.",
        "Define a Content-Security-Policy, starting in report-only mode.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options is absent, so browsers may MIME-sniff responses.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Neither X-Frame-Options nor a CSP frame-ancestors directive is present, "
        "so the page may be framed by third-party origins.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Referrer-Policy is not set; full URLs may leak to third-party origins.",
        "Set Referrer-Policy: strict-origin-when-cross-origin.",
    ),
}

# Patterns for material that should never appear in a public response body.
SECRET_PATTERNS = {
    "AWS access key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "Google API key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "Slack token": r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
    "Stripe secret key": r"\bsk_live_[0-9A-Za-z]{24,}\b",
    "GitHub token": r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",
    "Private key block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "JSON Web Token": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
}


async def security_headers(
    client: PoliteClient, result: ScanResult, target: str
) -> None:
    resp = await client.get(target)
    if resp is None:
        result.errors.append(f"could not reach {target} for header audit")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    csp = headers.get("content-security-policy", "")

    for name, (severity, summary, fix) in SECURITY_HEADERS.items():
        if name in headers:
            continue
        # frame-ancestors in CSP supersedes X-Frame-Options.
        if name == "x-frame-options" and "frame-ancestors" in csp:
            continue
        result.add(
            Finding(
                module="audit.headers",
                title=f"Missing security header: {name}",
                severity=severity,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=summary,
                evidence={"observed_headers": sorted(headers.keys())},
                remediation=fix,
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        )

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if match and int(match.group(1)) < 31536000:
            result.add(
                Finding(
                    module="audit.headers",
                    title="HSTS max-age is below one year",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    target=target,
                    summary=(
                        f"Strict-Transport-Security specifies max-age={match.group(1)}, "
                        "which is short enough to leave a meaningful downgrade window."
                    ),
                    evidence={"header": hsts},
                    remediation="Raise max-age to 31536000 or more.",
                )
            )


async def cors_policy(client: PoliteClient, result: ScanResult, target: str) -> None:
    """Check whether the server reflects an arbitrary Origin.

    Read-only: we send a normal GET with an Origin header and read what comes
    back. Nothing is modified.
    """
    probe_origin = "https://reconpal-origin-check.example"
    resp = await client.get(target, headers={"Origin": probe_origin})
    if resp is None:
        return

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    if acao == probe_origin:
        severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
        result.add(
            Finding(
                module="audit.cors",
                title="CORS policy reflects an arbitrary Origin",
                severity=severity,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    "The server echoed an attacker-supplied Origin in "
                    "Access-Control-Allow-Origin"
                    + (
                        " together with Access-Control-Allow-Credentials: true, which "
                        "lets any origin read authenticated responses."
                        if acac == "true"
                        else ". Credentials are not allowed, which limits impact, but "
                        "any origin can read unauthenticated responses."
                    )
                ),
                evidence={
                    "sent_origin": probe_origin,
                    "access-control-allow-origin": acao,
                    "access-control-allow-credentials": acac or "(absent)",
                },
                remediation=(
                    "Validate Origin against an allow-list rather than reflecting it. "
                    "Never combine a reflected origin with credentials."
                ),
            )
        )
    elif acao == "*" and acac == "true":
        # Browsers reject this pairing, but it signals a misunderstanding.
        result.add(
            Finding(
                module="audit.cors",
                title="Wildcard CORS origin combined with credentials",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    "Access-Control-Allow-Origin is '*' while credentials are "
                    "allowed. Browsers refuse this combination, so it is not "
                    "directly exploitable, but it indicates the CORS policy is not "
                    "doing what its author intended."
                ),
                evidence={"access-control-allow-origin": acao},
                remediation="Decide explicitly whether credentials are required.",
            )
        )


async def cookie_flags(client: PoliteClient, result: ScanResult, target: str) -> None:
    resp = await client.get(target)
    if resp is None:
        return

    raw_cookies = resp.headers.get_list("set-cookie")
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        missing = []
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "secure" not in lowered:
            missing.append("Secure")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if not missing:
            continue
        result.add(
            Finding(
                module="audit.cookies",
                title=f"Cookie {name} missing {', '.join(missing)}",
                severity=Severity.LOW if "HttpOnly" in missing else Severity.INFO,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    f"The cookie {name} is set without {', '.join(missing)}. Whether "
                    "this matters depends on what the cookie holds; a tracking "
                    "cookie without HttpOnly is not the same as a session cookie "
                    "without it."
                ),
                evidence={"set_cookie": raw[:200], "missing": missing},
                remediation="Set HttpOnly, Secure, and an explicit SameSite value.",
            )
        )


async def content_leakage(
    client: PoliteClient, result: ScanResult, target: str
) -> None:
    """Scan the landing page and its inline scripts for credential material."""
    resp = await client.get(target)
    if resp is None:
        return

    body = resp.text[:400_000]
    for label, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, body):
            token = match.group(0)
            redacted = token[:8] + "…" + token[-4:] if len(token) > 16 else token[:6] + "…"
            severity = Severity.INFO if label == "JSON Web Token" else Severity.HIGH
            result.add(
                Finding(
                    module="audit.disclosure",
                    title=f"Possible {label} in response body",
                    severity=severity,
                    confidence=Confidence.TENTATIVE,
                    target=target,
                    summary=(
                        f"A string matching the {label} format appears in the "
                        "response. Pattern matches are frequently false positives — "
                        "sample data, examples, or public identifiers — so verify "
                        "before treating this as a leak."
                    ),
                    evidence={"match_preview": redacted, "offset": match.start()},
                    remediation=(
                        "If genuine, revoke the credential and move it server-side."
                    ),
                )
            )
            break  # one finding per pattern is enough to prompt a look
