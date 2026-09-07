"""Model Context Protocol (MCP) deployment discovery.

Implements the unauthenticated stages of the reconnaissance methodology for MCP
servers: resource discovery, metadata cross-comparison, and registration-surface
mapping. Everything here is read-only apart from an optional client
registration, which is the protocol's own intended flow.

Reference: MCP authorization specification, version 2025-06-18.
https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

from ..core.http import PoliteClient
from ..core.models import Asset, Confidence, Finding, ScanResult, Severity

WELL_KNOWN = [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]

COMMON_MCP_PATHS = ["/mcp", "/sse", "/mcp/v1", "/api/mcp"]

SPEC_URL = "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization"


async def detect(client: PoliteClient, result: ScanResult, target: str) -> bool:
    """Look for a JSON-RPC MCP endpoint. Returns True if one appears to exist."""
    found = False
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "reconpal", "version": "1.0"},
        },
    }

    for path in COMMON_MCP_PATHS:
        url = urljoin(target + "/", path.lstrip("/"))
        resp = await client.post(
            url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        if resp is None:
            continue

        www_auth = resp.headers.get("www-authenticate", "")
        looks_mcp = (
            resp.status_code == 401
            and "bearer" in www_auth.lower()
        ) or _is_jsonrpc(resp.text)

        if not looks_mcp:
            continue

        found = True
        result.add_asset(
            Asset(
                kind="endpoint",
                value=url,
                detail=f"MCP JSON-RPC endpoint (HTTP {resp.status_code})",
                source="mcp probe",
            )
        )

        if resp.status_code == 401:
            # The spec requires the 401 to advertise the resource metadata URL
            # via WWW-Authenticate. Absence is a conformance gap, not a
            # vulnerability -- but it tells you the deployment has drifted.
            if "resource_metadata" not in www_auth:
                result.add(
                    Finding(
                        module="mcp.discovery",
                        title="401 omits resource_metadata in WWW-Authenticate",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        target=url,
                        summary=(
                            "The MCP specification requires a protected server to "
                            "indicate its resource metadata URL in the "
                            "WWW-Authenticate header of a 401 response. This "
                            "deployment does not, so conforming clients must fall "
                            "back to guessing well-known paths. This is a "
                            "specification conformance gap, not a vulnerability."
                        ),
                        evidence={
                            "status": resp.status_code,
                            "www-authenticate": www_auth or "(absent)",
                        },
                        remediation=(
                            "Include resource_metadata in WWW-Authenticate per "
                            "RFC 9728 section 5.1."
                        ),
                        references=[SPEC_URL,
                                    "https://datatracker.ietf.org/doc/html/rfc9728"],
                    )
                )
        elif resp.status_code == 200:
            result.add(
                Finding(
                    module="mcp.discovery",
                    title="MCP endpoint answered initialize without a token",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    target=url,
                    summary=(
                        "The endpoint returned a JSON-RPC response to an "
                        "unauthenticated initialize call. If tools/list is also "
                        "reachable, the full tool surface is exposed to anonymous "
                        "callers. Verify manually before reporting — authorization "
                        "is optional in MCP and some deployments are public by "
                        "design."
                    ),
                    evidence={"status": 200, "excerpt": resp.text[:300]},
                    remediation=(
                        "If the deployment is not intended to be public, require a "
                        "bearer token as described in the MCP authorization spec."
                    ),
                    references=[SPEC_URL],
                )
            )
        break

    return found


async def discovery_metadata(
    client: PoliteClient, result: ScanResult, target: str
) -> dict[str, dict]:
    """Fetch the three OAuth discovery documents and cross-compare them."""
    documents: dict[str, dict] = {}

    for path in WELL_KNOWN:
        url = urljoin(target + "/", path.lstrip("/"))
        resp = await client.get(url)
        if resp is None or resp.status_code != 200:
            continue
        try:
            doc = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue

        documents[path] = doc
        result.add_asset(
            Asset(
                kind="endpoint",
                value=url,
                detail="OAuth discovery document",
                source="mcp well-known",
            )
        )

    if not documents:
        return documents

    result.add(
        Finding(
            module="mcp.discovery",
            title=f"OAuth discovery metadata is publicly readable ({len(documents)}/3)",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            target=target,
            summary=(
                "Unauthenticated discovery metadata was retrieved. This is required "
                "behaviour for a conforming MCP server, not a weakness — it is "
                "recorded because it defines the authorization surface everything "
                "else is reached through."
            ),
            evidence={
                "documents": list(documents.keys()),
                **_metadata_summary(documents),
            },
            references=[SPEC_URL],
        )
    )

    _compare_documents(result, target, documents)
    _assess_auth_methods(result, target, documents)
    return documents


def _metadata_summary(documents: dict[str, dict]) -> dict:
    merged: dict = {}
    for doc in documents.values():
        for key in (
            "issuer",
            "registration_endpoint",
            "authorization_endpoint",
            "token_endpoint",
            "scopes_supported",
            "grant_types_supported",
            "token_endpoint_auth_methods_supported",
            "code_challenge_methods_supported",
        ):
            if key in doc and key not in merged:
                merged[key] = doc[key]
    return merged


def _compare_documents(
    result: ScanResult, target: str, documents: dict[str, dict]
) -> None:
    """Divergence between discovery documents means they are maintained separately."""
    if len(documents) < 2:
        return

    issuers = {path: doc.get("issuer") for path, doc in documents.items() if "issuer" in doc}
    distinct = {v for v in issuers.values() if v}
    if len(distinct) > 1:
        result.add(
            Finding(
                module="mcp.discovery",
                title="Discovery documents advertise inconsistent issuer values",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    "The discovery documents do not agree on the issuer identifier. "
                    "Clients validate tokens against the issuer, so disagreement "
                    "between documents means the answer depends on which document a "
                    "client happened to read."
                ),
                evidence={"issuers": issuers},
                remediation="Serve one canonical issuer value from all documents.",
                references=["https://datatracker.ietf.org/doc/html/rfc8414"],
            )
        )

    key_sets = {path: set(doc.keys()) for path, doc in documents.items()}
    if len(key_sets) >= 2:
        paths = list(key_sets)
        only_in = {
            p: sorted(key_sets[p] - set().union(*(key_sets[q] for q in paths if q != p)))
            for p in paths
        }
        divergent = {p: keys for p, keys in only_in.items() if keys}
        if divergent:
            result.add(
                Finding(
                    module="mcp.discovery",
                    title="Discovery documents expose differing field sets",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    target=target,
                    summary=(
                        "Fields present in one discovery document are absent from "
                        "another, which indicates they are generated independently. "
                        "Not a weakness in itself, but it predicts inconsistency "
                        "elsewhere in the deployment."
                    ),
                    evidence={"fields_unique_to_each_document": divergent},
                )
            )


def _assess_auth_methods(
    result: ScanResult, target: str, documents: dict[str, dict]
) -> None:
    merged = _metadata_summary(documents)
    methods = merged.get("token_endpoint_auth_methods_supported") or []
    pkce = merged.get("code_challenge_methods_supported") or []

    if methods and "none" in methods and len(methods) > 1:
        result.add(
            Finding(
                module="mcp.auth",
                title="Token endpoint accepts both public and secret-based clients",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                target=target,
                summary=(
                    "The authorization server advertises 'none' alongside "
                    f"secret-based methods ({', '.join(m for m in methods if m != 'none')}). "
                    "That is legitimate, but it is worth confirming that a client "
                    "registered as public cannot later authenticate with a shared "
                    "or guessable secret."
                ),
                evidence={"token_endpoint_auth_methods_supported": methods},
            )
        )

    if pkce and "S256" not in pkce:
        result.add(
            Finding(
                module="mcp.auth",
                title="PKCE S256 is not advertised",
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                target=target,
                summary=(
                    "The MCP specification requires clients to implement PKCE. The "
                    f"server advertises {pkce} without S256, which weakens "
                    "authorization-code interception protection."
                ),
                evidence={"code_challenge_methods_supported": pkce},
                remediation="Support and require the S256 code challenge method.",
                references=[SPEC_URL],
            )
        )


async def registration_surface(
    client: PoliteClient,
    result: ScanResult,
    documents: dict[str, dict],
    *,
    attempt_registration: bool = False,
) -> None:
    """Inspect Dynamic Client Registration.

    Open DCR is what the MCP specification asks for, so its mere presence is
    never reported as a weakness. The question worth asking is what a
    registration actually yields — which requires opting in, because
    registration creates state on the target.
    """
    merged = _metadata_summary(documents)
    endpoint = merged.get("registration_endpoint")
    if not endpoint:
        return

    result.add_asset(
        Asset(kind="endpoint", value=endpoint, detail="DCR endpoint",
              source="mcp metadata")
    )

    if not attempt_registration:
        result.add(
            Finding(
                module="mcp.registration",
                title="Dynamic Client Registration endpoint is advertised",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                target=endpoint,
                summary=(
                    "A registration endpoint is published. The MCP specification "
                    "recommends DCR support, so this is expected. Re-run with "
                    "--mcp-register to test what a registration returns; that "
                    "creates a client record on the target, so only do so when "
                    "scope permits."
                ),
                evidence={"registration_endpoint": endpoint},
                references=[SPEC_URL,
                            "https://datatracker.ietf.org/doc/html/rfc7591"],
            )
        )
        return

    body = {
        "client_name": "reconpal-assessment",
        "redirect_uris": ["http://localhost:8765/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }

    first = await client.post(
        endpoint, json=body, headers={"Content-Type": "application/json"}
    )
    if first is None or first.status_code not in (200, 201):
        return

    try:
        reg_a = first.json()
    except (json.JSONDecodeError, ValueError):
        return

    # Register a second time to see whether the "secret" is per-client.
    second = await client.post(
        endpoint, json=body, headers={"Content-Type": "application/json"}
    )
    reg_b = {}
    if second is not None and second.status_code in (200, 201):
        try:
            reg_b = second.json()
        except (json.JSONDecodeError, ValueError):
            reg_b = {}

    secret_a = reg_a.get("client_secret")
    secret_b = reg_b.get("client_secret")
    methods = merged.get("token_endpoint_auth_methods_supported") or []
    public_ok = "none" in methods

    if secret_a and secret_b and secret_a == secret_b:
        # Severity depends entirely on whether anything authenticates with it.
        severity = Severity.INFO if public_ok else Severity.MEDIUM
        result.add(
            Finding(
                module="mcp.registration",
                title="Registration returns an identical client_secret to every client",
                severity=severity,
                confidence=Confidence.CONFIRMED,
                target=endpoint,
                summary=(
                    "Two independent registrations received the same client_secret, "
                    "so the value is a shared constant rather than a per-client "
                    "credential."
                    + (
                        " The server advertises 'none' as a client authentication "
                        "method, so this is a public-client deployment where the "
                        "secret carries no security weight by design — recorded as "
                        "informational. It becomes material only if some endpoint "
                        "actually authenticates a client using this value."
                        if public_ok
                        else " The server does not advertise 'none', which suggests "
                        "client authentication is expected to mean something here. "
                        "Confirm whether the token endpoint accepts this shared "
                        "value as a credential."
                    )
                ),
                evidence={
                    "identical_across_registrations": True,
                    "secret_length": len(str(secret_a)),
                    "token_endpoint_auth_methods_supported": methods,
                },
                remediation=(
                    "Issue per-client secrets, or omit client_secret entirely for "
                    "public clients."
                ),
                references=["https://datatracker.ietf.org/doc/html/rfc7591"],
            )
        )

    if reg_a.get("client_id"):
        result.add_asset(
            Asset(
                kind="technology",
                value="Open Dynamic Client Registration",
                detail="registration succeeded without authentication",
                source="mcp registration",
            )
        )


def _is_jsonrpc(text: str) -> bool:
    try:
        doc = json.loads(text[:20_000])
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(doc, dict) and doc.get("jsonrpc") == "2.0"
