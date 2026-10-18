"""
Deterministic synthetic security telemetry for TraceGuard.

⚠️  SIMULATED DATA — does not represent real attacks or real infrastructure.

Design goals:
- ~50 nodes, ~80 relationships
- Mix of suspicious, benign, and ambiguous cases
- Shared IPs used by both legitimate and compromised accounts (realistic)
- Multi-hop paths that demonstrate graph traversal value
- Contradictory evidence (one ThreatIndicator on a shared IP doesn't condemn all users)
"""

from __future__ import annotations

NODES: dict[str, list[dict]] = {
    "Alert": [
        {
            "id": "ALT-001",
            "type": "BruteForce",
            "timestamp": "2026-01-15T02:14:33Z",
            "severity": "HIGH",
            "status": "OPEN",
            "description": "500 failed logins in 5 minutes from account acc-charlie",
        },
        {
            "id": "ALT-002",
            "type": "DataExfiltration",
            "timestamp": "2026-01-15T03:45:10Z",
            "severity": "CRITICAL",
            "status": "OPEN",
            "description": "Unusual outbound data transfer of 4.2 GB from dev-server-01",
        },
        {
            "id": "ALT-003",
            "type": "PrivilegeEscalation",
            "timestamp": "2026-01-15T09:12:55Z",
            "severity": "HIGH",
            "status": "OPEN",
            "description": "Account acc-delta acquired admin rights outside change window",
        },
        {
            "id": "ALT-004",
            "type": "LateralMovement",
            "timestamp": "2026-01-15T11:30:00Z",
            "severity": "MEDIUM",
            "status": "OPEN",
            "description": "Unusual SMB connections between workstations from acc-echo",
        },
        {
            "id": "ALT-005",
            "type": "AnomalousLogin",
            "timestamp": "2026-01-15T06:55:22Z",
            "severity": "LOW",
            "status": "OPEN",
            "description": "Login from new geolocation for acc-foxtrot (travel policy allowed)",
        },
        {
            "id": "ALT-006",
            "type": "MalwareDetected",
            "timestamp": "2026-01-16T00:05:01Z",
            "severity": "CRITICAL",
            "status": "OPEN",
            "description": "Ransomware signature detected on endpoint ws-006",
        },
    ],
    "Account": [
        {"id": "acc-alpha", "username": "alice.morgan", "department": "Engineering"},
        {"id": "acc-bravo", "username": "bob.smith", "department": "Finance"},
        {"id": "acc-charlie", "username": "charlie.xu", "department": "IT-Ops"},
        {"id": "acc-delta", "username": "diana.lee", "department": "HR"},
        {"id": "acc-echo", "username": "evan.jones", "department": "Engineering"},
        {"id": "acc-foxtrot", "username": "fiona.patel", "department": "Sales"},
        {"id": "acc-golf", "username": "gary.kim", "department": "Finance"},
        {"id": "acc-hotel", "username": "helen.wu", "department": "Security"},
        # Shared/contractor accounts
        {"id": "acc-india", "username": "ivan.contractor", "department": "Contractors"},
        {"id": "acc-juliet", "username": "julia.svc", "department": "ServiceAccounts"},
    ],
    "Device": [
        {"id": "dev-001", "hostname": "ws-alice-01", "criticality": "MEDIUM", "status": "HEALTHY"},
        {"id": "dev-002", "hostname": "ws-bob-02", "criticality": "MEDIUM", "status": "HEALTHY"},
        {"id": "dev-003", "hostname": "dev-server-01", "criticality": "HIGH", "status": "COMPROMISED"},
        {"id": "dev-004", "hostname": "ws-charlie-03", "criticality": "LOW", "status": "ISOLATED"},
        {"id": "dev-005", "hostname": "ws-diana-04", "criticality": "MEDIUM", "status": "HEALTHY"},
        {"id": "dev-006", "hostname": "ws-evan-05", "criticality": "MEDIUM", "status": "SUSPICIOUS"},
        {"id": "dev-007", "hostname": "ws-006", "criticality": "HIGH", "status": "COMPROMISED"},
        {"id": "dev-008", "hostname": "dc-primary", "criticality": "CRITICAL", "status": "HEALTHY"},
        {"id": "dev-009", "hostname": "file-server-01", "criticality": "HIGH", "status": "SUSPICIOUS"},
        {"id": "dev-010", "hostname": "ws-fiona-07", "criticality": "LOW", "status": "HEALTHY"},
    ],
    "IP": [
        # Known malicious exit node shared by several accounts
        {"address": "185.220.101.42", "reputation": "MALICIOUS", "first_seen": "2025-11-01"},
        # TOR exit node — suspicious but not proof of compromise
        {"address": "185.220.101.99", "reputation": "SUSPICIOUS", "first_seen": "2025-12-10"},
        # Legitimate corporate VPN
        {"address": "10.0.0.1", "reputation": "CLEAN", "first_seen": "2020-01-01"},
        # Employee home IP — also used by known threat actor (coincidence possible)
        {"address": "203.0.113.77", "reputation": "SUSPICIOUS", "first_seen": "2026-01-10"},
        # Cloud NAT — many users share this
        {"address": "34.102.136.180", "reputation": "CLEAN", "first_seen": "2023-06-01"},
        # Known C2 server
        {"address": "198.51.100.23", "reputation": "MALICIOUS", "first_seen": "2025-10-15"},
        # Legitimate CDN
        {"address": "104.16.0.0", "reputation": "CLEAN", "first_seen": "2021-03-01"},
        # Newly registered, no history
        {"address": "45.77.43.11", "reputation": "UNKNOWN", "first_seen": "2026-01-14"},
        # Fiona's travel IP — clean but new geolocation
        {"address": "89.187.191.50", "reputation": "CLEAN", "first_seen": "2026-01-15"},
    ],
    "ThreatIndicator": [
        {
            "id": "IOC-001",
            "type": "IPReputation",
            "source": "AbuseIPDB",
            "confidence": 0.95,
        },
        {
            "id": "IOC-002",
            "type": "TORExitNode",
            "source": "TorProject",
            "confidence": 0.90,
        },
        {
            "id": "IOC-003",
            "type": "C2Communication",
            "source": "ThreatFox",
            "confidence": 0.98,
        },
        {
            "id": "IOC-004",
            "type": "MalwareSignature",
            "source": "VirusTotal",
            "confidence": 0.99,
        },
        {
            "id": "IOC-005",
            "type": "IPReputation",
            "source": "AlienVault",
            "confidence": 0.65,  # lower confidence — shared IP, unclear attribution
        },
        {
            "id": "IOC-006",
            "type": "BruteForceSource",
            "source": "Shodan",
            "confidence": 0.88,
        },
        {
            "id": "IOC-007",
            "type": "DataExfiltrationEndpoint",
            "source": "NetworkMonitor",
            "confidence": 0.75,
        },
        {
            "id": "IOC-008",
            "type": "PhishingDomain",
            "source": "PhishTank",
            "confidence": 0.82,
        },
    ],
}

# Relationships: (from_label, from_id_field, from_id, rel_type, to_label, to_id_field, to_id, props)
RELATIONSHIPS: list[tuple] = [
    # Alert → Account (ON_ACCOUNT)
    ("Alert", "id", "ALT-001", "ON_ACCOUNT", "Account", "id", "acc-charlie", {"observed_at": "2026-01-15T02:14:33Z", "source_event_id": "EVT-1001"}),
    ("Alert", "id", "ALT-002", "ON_ACCOUNT", "Account", "id", "acc-alpha", {"observed_at": "2026-01-15T03:45:10Z", "source_event_id": "EVT-1002"}),
    ("Alert", "id", "ALT-003", "ON_ACCOUNT", "Account", "id", "acc-delta", {"observed_at": "2026-01-15T09:12:55Z", "source_event_id": "EVT-1003"}),
    ("Alert", "id", "ALT-004", "ON_ACCOUNT", "Account", "id", "acc-echo", {"observed_at": "2026-01-15T11:30:00Z", "source_event_id": "EVT-1004"}),
    ("Alert", "id", "ALT-005", "ON_ACCOUNT", "Account", "id", "acc-foxtrot", {"observed_at": "2026-01-15T06:55:22Z", "source_event_id": "EVT-1005"}),
    ("Alert", "id", "ALT-006", "ON_ACCOUNT", "Account", "id", "acc-echo", {"observed_at": "2026-01-16T00:05:01Z", "source_event_id": "EVT-1006"}),

    # Account → IP (USED_FROM)
    ("Account", "id", "acc-charlie", "USED_FROM", "IP", "address", "185.220.101.42", {"observed_at": "2026-01-15T02:10:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-charlie", "USED_FROM", "IP", "address", "10.0.0.1", {"observed_at": "2026-01-14T18:00:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-alpha", "USED_FROM", "IP", "address", "34.102.136.180", {"observed_at": "2026-01-15T03:44:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-alpha", "USED_FROM", "IP", "address", "10.0.0.1", {"observed_at": "2026-01-14T09:00:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-delta", "USED_FROM", "IP", "address", "203.0.113.77", {"observed_at": "2026-01-15T09:10:00Z", "confidence": 0.95}),
    ("Account", "id", "acc-echo", "USED_FROM", "IP", "address", "198.51.100.23", {"observed_at": "2026-01-15T11:25:00Z", "confidence": 0.98}),
    ("Account", "id", "acc-echo", "USED_FROM", "IP", "address", "10.0.0.1", {"observed_at": "2026-01-14T16:00:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-foxtrot", "USED_FROM", "IP", "address", "89.187.191.50", {"observed_at": "2026-01-15T06:54:00Z", "confidence": 0.98}),
    ("Account", "id", "acc-india", "USED_FROM", "IP", "address", "185.220.101.42", {"observed_at": "2026-01-14T23:00:00Z", "confidence": 0.90}),
    ("Account", "id", "acc-india", "USED_FROM", "IP", "address", "45.77.43.11", {"observed_at": "2026-01-14T22:00:00Z", "confidence": 0.85}),
    ("Account", "id", "acc-golf", "USED_FROM", "IP", "address", "203.0.113.77", {"observed_at": "2026-01-14T14:00:00Z", "confidence": 0.80}),
    ("Account", "id", "acc-hotel", "USED_FROM", "IP", "address", "10.0.0.1", {"observed_at": "2026-01-15T08:00:00Z", "confidence": 0.99}),
    ("Account", "id", "acc-juliet", "USED_FROM", "IP", "address", "198.51.100.23", {"observed_at": "2026-01-15T10:00:00Z", "confidence": 0.97}),
    ("Account", "id", "acc-bravo", "USED_FROM", "IP", "address", "34.102.136.180", {"observed_at": "2026-01-15T10:30:00Z", "confidence": 0.99}),

    # Account → Device (ACCESSED)
    ("Account", "id", "acc-charlie", "ACCESSED", "Device", "id", "dev-004", {"observed_at": "2026-01-15T01:55:00Z", "source_event_id": "EVT-2001"}),
    ("Account", "id", "acc-charlie", "ACCESSED", "Device", "id", "dev-003", {"observed_at": "2026-01-15T02:05:00Z", "source_event_id": "EVT-2002"}),
    ("Account", "id", "acc-alpha", "ACCESSED", "Device", "id", "dev-001", {"observed_at": "2026-01-15T03:40:00Z", "source_event_id": "EVT-2003"}),
    ("Account", "id", "acc-alpha", "ACCESSED", "Device", "id", "dev-003", {"observed_at": "2026-01-15T03:42:00Z", "source_event_id": "EVT-2004"}),
    ("Account", "id", "acc-delta", "ACCESSED", "Device", "id", "dev-005", {"observed_at": "2026-01-15T09:05:00Z", "source_event_id": "EVT-2005"}),
    ("Account", "id", "acc-delta", "ACCESSED", "Device", "id", "dev-008", {"observed_at": "2026-01-15T09:11:00Z", "source_event_id": "EVT-2006"}),
    ("Account", "id", "acc-echo", "ACCESSED", "Device", "id", "dev-006", {"observed_at": "2026-01-15T11:20:00Z", "source_event_id": "EVT-2007"}),
    ("Account", "id", "acc-echo", "ACCESSED", "Device", "id", "dev-007", {"observed_at": "2026-01-16T00:00:00Z", "source_event_id": "EVT-2008"}),
    ("Account", "id", "acc-echo", "ACCESSED", "Device", "id", "dev-009", {"observed_at": "2026-01-15T11:25:00Z", "source_event_id": "EVT-2009"}),
    ("Account", "id", "acc-foxtrot", "ACCESSED", "Device", "id", "dev-010", {"observed_at": "2026-01-15T06:55:00Z", "source_event_id": "EVT-2010"}),
    ("Account", "id", "acc-india", "ACCESSED", "Device", "id", "dev-003", {"observed_at": "2026-01-14T23:05:00Z", "source_event_id": "EVT-2011"}),

    # Device → IP (CONNECTED_TO)
    ("Device", "id", "dev-003", "CONNECTED_TO", "IP", "address", "198.51.100.23", {"observed_at": "2026-01-15T03:50:00Z", "source_event_id": "EVT-3001"}),
    ("Device", "id", "dev-003", "CONNECTED_TO", "IP", "address", "45.77.43.11", {"observed_at": "2026-01-14T23:10:00Z", "source_event_id": "EVT-3002"}),
    ("Device", "id", "dev-004", "CONNECTED_TO", "IP", "address", "185.220.101.42", {"observed_at": "2026-01-15T02:12:00Z", "source_event_id": "EVT-3003"}),
    ("Device", "id", "dev-006", "CONNECTED_TO", "IP", "address", "198.51.100.23", {"observed_at": "2026-01-15T11:26:00Z", "source_event_id": "EVT-3004"}),
    ("Device", "id", "dev-007", "CONNECTED_TO", "IP", "address", "185.220.101.99", {"observed_at": "2026-01-16T00:03:00Z", "source_event_id": "EVT-3005"}),
    ("Device", "id", "dev-007", "CONNECTED_TO", "IP", "address", "45.77.43.11", {"observed_at": "2026-01-15T23:50:00Z", "source_event_id": "EVT-3006"}),
    ("Device", "id", "dev-009", "CONNECTED_TO", "IP", "address", "45.77.43.11", {"observed_at": "2026-01-15T11:27:00Z", "source_event_id": "EVT-3007"}),
    ("Device", "id", "dev-001", "CONNECTED_TO", "IP", "address", "34.102.136.180", {"observed_at": "2026-01-15T03:41:00Z", "source_event_id": "EVT-3008"}),
    ("Device", "id", "dev-005", "CONNECTED_TO", "IP", "address", "10.0.0.1", {"observed_at": "2026-01-15T09:00:00Z", "source_event_id": "EVT-3009"}),
    ("Device", "id", "dev-010", "CONNECTED_TO", "IP", "address", "89.187.191.50", {"observed_at": "2026-01-15T06:56:00Z", "source_event_id": "EVT-3010"}),

    # IP → ThreatIndicator (HAS_INDICATOR)
    ("IP", "address", "185.220.101.42", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-001", {"observed_at": "2025-11-01", "confidence": 0.95}),
    ("IP", "address", "185.220.101.42", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-006", {"observed_at": "2026-01-15", "confidence": 0.88}),
    ("IP", "address", "185.220.101.99", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-002", {"observed_at": "2025-12-10", "confidence": 0.90}),
    ("IP", "address", "198.51.100.23", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-003", {"observed_at": "2025-10-15", "confidence": 0.98}),
    ("IP", "address", "198.51.100.23", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-007", {"observed_at": "2026-01-15", "confidence": 0.75}),
    ("IP", "address", "203.0.113.77", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-005", {"observed_at": "2026-01-10", "confidence": 0.65}),
    ("IP", "address", "45.77.43.11", "HAS_INDICATOR", "ThreatIndicator", "id", "IOC-008", {"observed_at": "2026-01-14", "confidence": 0.82}),
]
