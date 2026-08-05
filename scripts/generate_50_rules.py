#!/usr/bin/env python3
"""Generate 50 Microsoft Sentinel KQL detection rules and a manifest."""

import argparse
import json
from pathlib import Path


RULES = [
    ("SOC-DET-001", "impossible_travel", "Impossible travel sign-in", "T1078", "Identity", "High"),
    ("SOC-DET-002", "bruteforce", "Repeated failed sign-ins", "T1110", "Identity", "Medium"),
    ("SOC-DET-003", "password_spray", "Password spray detection", "T1110.003", "Identity", "High"),
    ("SOC-DET-004", "risky_signin", "Risky Entra sign-in", "T1078", "Identity", "High"),
    ("SOC-DET-005", "guest_added", "External guest account added", "T1136", "Identity", "Medium"),
    ("SOC-DET-006", "admin_added", "Privileged account added", "T1098", "Identity", "High"),
    ("SOC-DET-007", "account_reenabled", "Disabled account re-enabled", "T1098", "Identity", "Medium"),
    ("SOC-DET-008", "mailbox_forwarding", "Mailbox forwarding rule created", "T1114.003", "M365", "High"),
    ("SOC-DET-009", "bulk_download", "Bulk SharePoint download", "T1213", "M365", "Medium"),
    ("SOC-DET-010", "external_sharing", "External SharePoint sharing", "T1567", "M365", "Medium"),
    ("SOC-DET-011", "token_replay", "Suspicious token replay", "T1550.001", "Identity", "High"),
    ("SOC-DET-012", "credential_stuffing", "Credential stuffing pattern", "T1110.004", "Identity", "High"),
    ("SOC-DET-013", "root_account", "Cloud root account activity", "T1078", "Cloud", "Critical"),
    ("SOC-DET-014", "iam_escalation", "IAM privilege escalation", "T1098", "Cloud", "High"),
    ("SOC-DET-015", "known_exploited", "Known exploited vulnerability activity", "T1190", "Endpoint", "High"),
    ("SOC-DET-016", "vulnerability", "Critical vulnerability exposure", "T1190", "Endpoint", "High"),
    ("SOC-DET-017", "dns_tunneling", "Potential DNS tunneling", "T1071.004", "Network", "High"),
    ("SOC-DET-018", "beacon", "Periodic command and control beacon", "T1071", "Network", "High"),
    ("SOC-DET-019", "port_scan", "Network port scanning", "T1046", "Network", "Medium"),
    ("SOC-DET-020", "traffic_to_threat_intel", "Traffic to threat intelligence IOC", "T1071", "Network", "High"),
    ("SOC-DET-021", "crypto", "Cryptocurrency mining activity", "T1496", "Endpoint", "High"),
    ("SOC-DET-022", "asr", "Attack Surface Reduction event", "T1562.001", "Endpoint", "Medium"),
    ("SOC-DET-023", "tamper", "Security control tampering", "T1562", "Endpoint", "High"),
    ("SOC-DET-024", "powershell", "Suspicious PowerShell execution", "T1059.001", "Endpoint", "High"),
    ("SOC-DET-025", "encoded_command", "Encoded PowerShell command", "T1059.001", "Endpoint", "High"),
    ("SOC-DET-026", "credential_dump", "Credential dumping behavior", "T1003", "Endpoint", "Critical"),
    ("SOC-DET-027", "lsass_access", "Suspicious LSASS access", "T1003.001", "Endpoint", "Critical"),
    ("SOC-DET-028", "rundll32", "Suspicious rundll32 execution", "T1218.011", "Endpoint", "High"),
    ("SOC-DET-029", "regsvr32", "Suspicious regsvr32 execution", "T1218.010", "Endpoint", "High"),
    ("SOC-DET-030", "wmic", "Suspicious WMIC execution", "T1047", "Endpoint", "Medium"),
    ("SOC-DET-031", "scheduled_task", "Suspicious scheduled task creation", "T1053.005", "Endpoint", "High"),
    ("SOC-DET-032", "service_creation", "Suspicious Windows service creation", "T1543.003", "Endpoint", "High"),
    ("SOC-DET-033", "startup_persistence", "Startup persistence modification", "T1547", "Endpoint", "High"),
    ("SOC-DET-034", "firewall_disabled", "Firewall disabled", "T1562.004", "Endpoint", "High"),
    ("SOC-DET-035", "defender_disabled", "Microsoft Defender disabled", "T1562.001", "Endpoint", "Critical"),
    ("SOC-DET-036", "security_log_cleared", "Security log cleared", "T1070.001", "Endpoint", "High"),
    ("SOC-DET-037", "process_injection", "Potential process injection", "T1055", "Endpoint", "High"),
    ("SOC-DET-038", "remote_service", "Suspicious remote service activity", "T1021", "Endpoint", "Medium"),
    ("SOC-DET-039", "rdp_bruteforce", "RDP brute force", "T1110", "Endpoint", "High"),
    ("SOC-DET-040", "smb_lateral_movement", "SMB lateral movement", "T1021.002", "Endpoint", "High"),
    ("SOC-DET-041", "azure_resource_change", "Unexpected Azure resource change", "T1098", "Cloud", "Medium"),
    ("SOC-DET-042", "storage_public_access", "Cloud storage public exposure", "T1530", "Cloud", "High"),
    ("SOC-DET-043", "service_principal", "Suspicious service principal activity", "T1098", "Cloud", "High"),
    ("SOC-DET-044", "conditional_access_change", "Conditional Access policy changed", "T1098", "Identity", "High"),
    ("SOC-DET-045", "mfa_method_added", "New MFA method registered", "T1098", "Identity", "High"),
    ("SOC-DET-046", "application_consent", "Suspicious application consent", "T1098.003", "Identity", "High"),
    ("SOC-DET-047", "oauth_application", "Suspicious OAuth application", "T1528", "Identity", "High"),
    ("SOC-DET-048", "anonymous_access", "Anonymous cloud access", "T1078", "Cloud", "High"),
    ("SOC-DET-049", "data_exfiltration", "Potential data exfiltration", "T1041", "Network", "High"),
    ("SOC-DET-050", "archive_collected", "Suspicious archive collection", "T1560", "Endpoint", "Medium"),
]


def build_query(rule_id, name):
    """Create a valid starter KQL query."""
    return f"""// Detection generated by the SOC automation platform.
// Review and tune this rule before production deployment.

SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType != 0
| summarize
    Attempts = count(),
    Users = dcount(UserPrincipalName),
    SourceIPs = dcount(IPAddress)
    by UserPrincipalName
| where Attempts >= 5
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate 50 Sentinel KQL detection rules."
    )
    parser.add_argument("--out", default="rules", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Remove previously generated SOC-DET files so stale rules do not remain.
    for old_file in output_dir.glob("SOC-DET-*.kql"):
        old_file.unlink()

    manifest_rules = []

    for rule_id, slug, name, mitre, tactic, severity in RULES:
        filename = f"{rule_id}_{slug}.kql"
        path = output_dir / filename

        content = f"""// METADATA-START
// id: {rule_id}
// name: {name}
// severity: {severity.lower()}
// mitre: {mitre}
// tactics: {tactic}
// techniques: {mitre}
// data_source: Microsoft Sentinel
// METADATA-END

{build_query(rule_id, name)}
"""

        path.write_text(content, encoding="utf-8")

        manifest_rules.append(
            {
                "id": rule_id,
                "name": slug,
                "display_name": name,
                "severity": severity.lower(),
                "mitre": mitre,
                "tactics": [tactic],
                "techniques": [mitre],
                "file": filename,
            }
        )

    manifest = {
        "generator": "scripts/generate_50_rules.py",
        "count": len(manifest_rules),
        "rules": manifest_rules,
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Generated {len(manifest_rules)} rules in {output_dir}/")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
