#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


RULES = [
    (
        "SOC-DET-001",
        "suspicious_signin",
        "High",
        "T1078",
        "SigninLogs",
        "Entra ID",
        '''SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          AppDisplayName, ResultDescription'''
    ),

    (
        "SOC-DET-002",
        "impossible_travel",
        "High",
        "T1078",
        "SigninLogs",
        "Entra ID",
        '''SigninLogs
| where ResultType == 0
| summarize
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Locations=make_set(Location)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1'''
    ),

    (
        "SOC-DET-003",
        "multiple_failed_signins",
        "Medium",
        "T1110",
        "SigninLogs",
        "Entra ID",
        '''SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 10'''
    ),

    (
        "SOC-DET-004",
        "privileged_role_assignment",
        "High",
        "T1098",
        "AuditLogs",
        "Entra ID",
        '''AuditLogs
| where OperationName has_any (
    "Add member to role",
    "Add eligible member to role",
    "Add permanent member to role"
)
| project TimeGenerated, InitiatedBy,
          TargetResources, OperationName'''
    ),

    (
        "SOC-DET-005",
        "sensitive_file_access",
        "Medium",
        "T1530",
        "CloudAppEvents",
        "Microsoft Defender for Cloud Apps",
        '''CloudAppEvents
| where ActionType has_any (
    "FileDownloaded",
    "FileAccessed",
    "FileUploaded"
)
| where ObjectName has_any (
    "password",
    "credential",
    "secret",
    "confidential"
)
| project TimeGenerated, AccountDisplayName,
          ActionType, ObjectName'''
    ),

    (
        "SOC-DET-006",
        "mailbox_forwarding_rule",
        "High",
        "T1098",
        "OfficeActivity",
        "Microsoft 365",
        '''OfficeActivity
| where Operation has_any (
    "New-InboxRule",
    "Set-InboxRule"
)
| where Parameters has_any (
    "ForwardTo",
    "RedirectTo",
    "ForwardAsAttachmentTo"
)
| project TimeGenerated, UserId,
          Operation, Parameters'''
    ),

    (
        "SOC-DET-007",
        "azure_resource_change",
        "Medium",
        "T1098",
        "AzureActivity",
        "Azure",
        '''AzureActivity
| where ActivityStatusValue == "Succeeded"
| where OperationNameValue has_any (
    "write",
    "delete",
    "action"
)
| project TimeGenerated, Caller,
          OperationNameValue, ResourceGroup, Resource'''
    ),

    (
        "SOC-DET-008",
        "defender_high_severity_alert",
        "High",
        "T1059",
        "AlertInfo",
        "Microsoft Defender XDR",
        '''AlertInfo
| where Severity in ("High", "Critical")
| project Timestamp, AlertId,
          Title, Severity, Category'''
    ),

    (
        "SOC-DET-009",
        "suspicious_dns_query",
        "Medium",
        "T1071",
        "DnsEvents",
        "DNS",
        '''DnsEvents
| where QueryName has_any (
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".mov"
)
| project TimeGenerated, Computer,
          ClientIP, Name, QueryType'''
    ),

    (
        "SOC-DET-010",
        "sensitive_label_access",
        "Medium",
        "T1530",
        "CloudAppEvents",
        "Microsoft 365",
        '''CloudAppEvents
| where ActionType has_any (
    "FileDownloaded",
    "FileAccessed",
    "FileUploaded"
)
| where SensitivityLabel contains "Confidential"
| project TimeGenerated,
          AccountDisplayName,
          ActionType,
          ObjectName,
          SensitivityLabel'''
    ),
]


def main():
    parser = argparse.ArgumentParser(
        description="Generate Sentinel KQL detection rules."
    )

    parser.add_argument(
        "--out",
        default="rules",
        help="Output directory"
    )

    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    manifest = []

    for rid, name, severity, mitre, table, source, query in RULES:

        tactic = mitre.split(".")[0]

        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in name
        )

        header = (
            "// METADATA-START\n"
            f"// id: {rid} | name: {name} | severity: {severity}\n"
            f"// mitre: {mitre} | nist: DE.CM-7 | "
            "iso27001: A.8.16 | soc2: CC7.2\n"
            f"// data_source: {source} | table: {table}\n"
            "// METADATA-END\n\n"
        )

        rule_file = out / f"{rid}_{safe_name}.kql"

        rule_file.write_text(
            header + query.strip() + "\n",
            encoding="utf-8"
        )

        manifest.append(
            {
                "id": rid,
                "name": name,
                "severity": severity,
                "tactics": [tactic],
                "query": query.strip(),
                "table": table,
                "source": source,
            }
        )

    manifest_file = out / "manifest.json"

    manifest_file.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8"
    )

    print(f"Generated {len(RULES)} rules -> {out}/")
    print(f"Manifest -> {manifest_file}")


if __name__ == "__main__":
    main()
