"""
Explainable, deterministic risk scoring engine for TraceGuard.

Scores are additive with named evidence items. Each contributor
is returned so the UI can render a transparent breakdown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScoreFactor:
    name: str
    points: float
    reason: str
    evidence_ref: str | None = None


@dataclass
class RiskScore:
    score: float
    verdict: str              # CRITICAL / HIGH / MEDIUM / LOW / BENIGN
    factors: list[ScoreFactor] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "verdict": self.verdict,
            "factors": [
                {
                    "name": f.name,
                    "points": f.points,
                    "reason": f.reason,
                    "evidence_ref": f.evidence_ref,
                }
                for f in self.factors
            ],
            "uncertainties": self.uncertainties,
            "capped": self.capped,
        }


# ---------------------------------------------------------------------------
# Weight configuration — easily tuneable
# ---------------------------------------------------------------------------

WEIGHTS = {
    # Alert severity
    "severity_critical": 30,
    "severity_high": 25,
    "severity_medium": 15,
    "severity_low": 5,

    # Threat indicator confidence × multiplier
    "high_confidence_ioc": 30,       # confidence >= 0.90
    "medium_confidence_ioc": 18,     # confidence >= 0.70
    "low_confidence_ioc": 8,         # confidence < 0.70

    # IP reputation
    "malicious_ip": 20,
    "suspicious_ip": 8,

    # Device criticality
    "critical_device_compromised": 25,
    "high_device_compromised": 18,
    "device_suspicious": 10,

    # Lateral movement signal
    "lateral_movement_type": 12,

    # Multi-hop evidence depth
    "multi_hop_depth_bonus": 5,      # added once when paths ≥ 2 hops

    # Mitigation
    "clean_ip_only": -10,            # account only used clean IPs
    "shared_ip_low_confidence": -8,  # shared IP context lowers weight
}

MAX_SCORE = 100


def _verdict(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "BENIGN"


def calculate_risk(
    alert_context: dict[str, Any],
    threat_paths: dict[str, Any],
    device_data: dict[str, Any],
    related_accounts: dict[str, Any],
) -> RiskScore:
    """
    Compute a risk score from graph evidence.

    All parameters come directly from repository query results — never
    synthesized by an LLM.
    """
    factors: list[ScoreFactor] = []
    uncertainties: list[str] = []
    score = 0.0

    alert = alert_context.get("alert") or {}

    # ── 1. Alert severity ────────────────────────────────────────────────────
    severity = (alert.get("severity") or "LOW").upper()
    sev_weights = {
        "CRITICAL": ("severity_critical", "Critical-severity alert"),
        "HIGH": ("severity_high", "High-severity alert"),
        "MEDIUM": ("severity_medium", "Medium-severity alert"),
        "LOW": ("severity_low", "Low-severity alert"),
    }
    wk, reason = sev_weights.get(severity, ("severity_low", "Low-severity alert"))
    pts = WEIGHTS[wk]
    score += pts
    factors.append(ScoreFactor(name="Alert Severity", points=pts, reason=reason))

    # ── 2. Alert type bonus ──────────────────────────────────────────────────
    alert_type = (alert.get("type") or "").lower()
    if "lateral" in alert_type:
        score += WEIGHTS["lateral_movement_type"]
        factors.append(ScoreFactor(
            name="Lateral Movement Indicator",
            points=WEIGHTS["lateral_movement_type"],
            reason="Alert type indicates lateral movement — elevated risk",
        ))

    # ── 3. Threat indicator evidence ─────────────────────────────────────────
    paths = threat_paths.get("paths") or []
    seen_iocs: set[str] = set()
    seen_ip_reputations: set[str] = set()
    best_ioc_by_ip: dict[str, tuple[dict[str, Any], str]] = {}

    for path in paths:
        ioc = path.get("indicator") or {}
        ioc_id = ioc.get("id", "")
        ip = path.get("ip") or {}
        ip_rep = (ip.get("reputation") or "UNKNOWN").upper()

        # IP reputation
        ip_address = ip.get("address")
        if ip_rep == "MALICIOUS" and ip_address not in seen_ip_reputations:
            score += WEIGHTS["malicious_ip"]
            factors.append(ScoreFactor(
                name="Malicious IP",
                points=WEIGHTS["malicious_ip"],
                reason=f"Account used from known-malicious IP {ip_address}",
                evidence_ref=ip_address,
            ))
            seen_ip_reputations.add(ip_address)
        elif ip_rep == "SUSPICIOUS" and ip_address not in seen_ip_reputations:
            score += WEIGHTS["suspicious_ip"]
            factors.append(ScoreFactor(
                name="Suspicious IP",
                points=WEIGHTS["suspicious_ip"],
                reason=f"Account used from suspicious IP {ip_address}",
                evidence_ref=ip_address,
            ))
            seen_ip_reputations.add(ip_address)

        # Keep the strongest indicator per IP. Multiple feeds describing the
        # same endpoint are corroboration, not independent endpoint evidence.
        if ioc_id:
            current = best_ioc_by_ip.get(ip_address or "")
            confidence = float(ioc.get("confidence") or 0.5)
            if current is None or confidence > float(current[0].get("confidence") or 0.5):
                best_ioc_by_ip[ip_address or ""] = (ioc, ioc_id)

    for ioc, ioc_id in best_ioc_by_ip.values():
        if ioc_id in seen_iocs:
            continue
        confidence = float(ioc.get("confidence") or 0.5)
        if confidence >= 0.90:
            w = WEIGHTS["high_confidence_ioc"]
            label = "High-Confidence IOC"
        elif confidence >= 0.70:
            w = WEIGHTS["medium_confidence_ioc"]
            label = "Medium-Confidence IOC"
        else:
            w = WEIGHTS["low_confidence_ioc"]
            label = "Low-Confidence IOC"
            uncertainties.append(
                f"IOC {ioc_id} has confidence {confidence:.0%} — "
                "shared infrastructure may implicate multiple unrelated accounts."
            )

        score += w
        factors.append(ScoreFactor(
            name=label,
            points=w,
            reason=f"{ioc.get('type')} from {ioc.get('source')} (confidence {confidence:.0%})",
            evidence_ref=ioc_id,
        ))
        seen_iocs.add(ioc_id)

    # Multi-hop depth bonus
    distinct_path_ips = {path.get("ip", {}).get("address") for path in paths}
    distinct_path_ips.discard(None)
    if len(distinct_path_ips) >= 2:
        score += WEIGHTS["multi_hop_depth_bonus"]
        factors.append(ScoreFactor(
            name="Multi-Hop Evidence",
            points=WEIGHTS["multi_hop_depth_bonus"],
            reason=f"{len(distinct_path_ips)} distinct IP paths discovered — corroborating evidence",
        ))

    # ── 4. Device evidence ───────────────────────────────────────────────────
    devices = device_data.get("devices") or []
    for dev_entry in devices:
        dev = dev_entry.get("device") or {}
        criticality = (dev.get("criticality") or "LOW").upper()
        status = (dev.get("status") or "HEALTHY").upper()

        if status == "COMPROMISED":
            if criticality == "CRITICAL":
                w = WEIGHTS["critical_device_compromised"]
            elif criticality == "HIGH":
                w = WEIGHTS["high_device_compromised"]
            else:
                w = WEIGHTS["device_suspicious"]
            score += w
            factors.append(ScoreFactor(
                name="Compromised Device",
                points=w,
                reason=f"{dev.get('hostname')} ({criticality} criticality) is COMPROMISED",
                evidence_ref=dev.get("id"),
            ))
        elif status == "SUSPICIOUS":
            score += WEIGHTS["device_suspicious"]
            factors.append(ScoreFactor(
                name="Suspicious Device",
                points=WEIGHTS["device_suspicious"],
                reason=f"{dev.get('hostname')} flagged as SUSPICIOUS",
                evidence_ref=dev.get("id"),
            ))

    # ── 5. Related account analysis ──────────────────────────────────────────
    related = related_accounts.get("related_accounts") or []
    direct_related = [r for r in related if r.get("connection_type") == "DIRECT"]
    indirect_related = [r for r in related if r.get("connection_type") == "INDIRECT"]

    if direct_related:
        # Shared IPs: note as uncertainty, not evidence of compromise
        names = [r["account"].get("username", "?") for r in direct_related]
        uncertainties.append(
            f"Accounts {', '.join(names)} share the same IP — "
            "this may reflect shared NAT/VPN rather than coordinated activity."
        )

    if indirect_related:
        uncertainties.append(
            f"{len(indirect_related)} account(s) share a threat indicator via different IPs — "
            "possible infrastructure overlap."
        )

    # ── 6. No threat paths found ─────────────────────────────────────────────
    if not paths and not devices:
        uncertainties.append(
            "No threat paths or device connections found. "
            "The graph may lack telemetry for this alert. "
            "Score based solely on alert metadata."
        )

    # ── 7. Cap score ─────────────────────────────────────────────────────────
    capped = score > MAX_SCORE
    final_score = min(score, MAX_SCORE)

    return RiskScore(
        score=final_score,
        verdict=_verdict(final_score),
        factors=factors,
        uncertainties=uncertainties,
        capped=capped,
    )
