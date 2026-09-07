"""Data models for ReconPal findings and scan state."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity. Ordered so comparisons work as expected."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def colour(self) -> str:
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "grey62",
        }[self]


class Confidence(str, Enum):
    """How sure we are. Kept separate from severity on purpose.

    A finding can be severe if real but only tentatively observed. Collapsing
    the two into one number is how scanners end up crying wolf.
    """

    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    TENTATIVE = "Tentative"


@dataclass
class Finding:
    """One observation about a target.

    `evidence` holds the raw material a human needs to verify the claim without
    re-running the scan. Anything asserted in `summary` should be traceable to it.
    """

    module: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Asset:
    """Something discovered that is not itself a finding: a host, path, or tech."""

    kind: str  # "subdomain" | "endpoint" | "technology" | "port"
    value: str
    detail: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything one scan produced."""

    target: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    finished_at: str = ""
    modules_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    request_count: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_asset(self, asset: Asset) -> None:
        # Cheap dedupe; asset lists get noisy fast.
        for existing in self.assets:
            if existing.kind == asset.kind and existing.value == asset.value:
                return
        self.assets.append(asset)

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def highest(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def assets_of(self, kind: str) -> list[Asset]:
        return [a for a in self.assets if a.kind == kind]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.module, f.title))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "modules_run": self.modules_run,
            "request_count": self.request_count,
            "summary": {
                "total_findings": len(self.findings),
                "highest_severity": self.highest.value if self.highest else None,
                "counts": self.counts,
                "assets_discovered": len(self.assets),
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "assets": [a.to_dict() for a in self.assets],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
