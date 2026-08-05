#!/usr/bin/env python3
"""Generate 50 Sentinel analytics rules (KQL) with compliance metadata headers.
Usage: python3 scripts/generate_50_rules.py --out rules"""
import argparse, json
from pathlib import Path

RULES = [
# ---- IDENTITY (Entra ID / SigninLogs / AuditLogs) ----
("SOC-DET-101","impossible_travel","high","T1078","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(1d)
| summarize IPs = dcount(IPAddress), Locations = dcount(Location) by UserPrincipalName
| where Locations > 2 or IPs > 3"""),
("SOC-DET-102","risky_signin_high","high","T1078","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(1d)
| where RiskLevelDuringSignIn == "high" or RiskLevelAggregated == "high"
| where ResultType == "0""""),
("SOC-DET-103","legacy_auth_success","medium","T1078","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(7d)
| where ClientAppUsed in ("POP3","IMAP4","SMTP","Other clients") | where ResultType == "0""""),
("SOC-DET-104","mfa_failure_burst","medium","T1110","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(15m)
| where ResultType == "500121" | summarize Failures = count() by UserPrincipalName, IPAddress
| where Failures > 5"""),
("SOC-DET-105","privileged_role_activation","high","T1078","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where ActivityDisplayName has "Activate" and ActivityDisplayName has "role"
| where Result == "success""""),
("SOC-DET-106","admin_added_to_role","high","T1098","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where ActivityDisplayName == "Add member to role"
| extend Member = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(TargetResources[0].displayName)"""),
("SOC-DET-107","sp_credential_added","high","T1098","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where ActivityDisplayName == "Add service principal credentials"
| where Result == "success""""),
("SOC-DET-108","guest_added_to_admin","critical","T1098","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where ActivityDisplayName == "Add member to role"
| where TargetResources[0].userPrincipalName has "#EXT#" """,),
("SOC-DET-109","account_reenabled","medium","T1078","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(2d)
| where ActivityDisplayName == "Update user"
| where TargetResources[0].modifiedProperties has "accountEnabled" """,),
("SOC-DET-110","password_spray","medium","T1110","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize Attempts = count(), Users = dcount(UserPrincipalName) by IPAddress
| where Attempts > 20 or Users > 10"""),
("SOC-DET-111","token_replay_multiple_ip","high","T1110","SigninLogs","Entra ID",
 """SigninLogs | where TimeGenerated > ago(1h) | where ResultType == "0"
| summarize IPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 5m)
| where IPs > 1"""),
("SOC-DET-112","app_consent_grant","medium","T1098","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where ActivityDisplayName == "Consent to application" | where Result == "success""""),
("SOC-DET-113","mailbox_forwarding_rule","high","T1114.003","OfficeActivity","Exchange",
 """OfficeActivity | where TimeGenerated > ago(1d)
| where Operation == "New-InboxRule" | where Parameters has "ForwardTo" or Parameters has "RedirectTo""""),
("SOC-DET-114","spf_dkim_change","high","T1562.002","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where OperationName has "Set-DomainAuthentication" | where Result == "success""""),
("SOC-DET-115","tenant_config_change","high","T1484","AuditLogs","Entra ID",
 """AuditLogs | where TimeGenerated > ago(1d)
| where OperationName has_any ("Set-OrganizationConfig","New-MultiTenantOrganization","Set-DefaultTenant")""""),
# ---- ENDPOINT (Defender for Endpoint) ----
("SOC-DET-116","powershell_encoded","high","T1059.001","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where FileName == "powershell.exe"
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "EncodedCommand""""),
("SOC-DET-117","lolbin_network","high","T1218","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where FileName in ("rundll32.exe","mshta.exe","regsvr32.exe")
| where ProcessCommandLine has "http" or ProcessCommandLine has "url.dll""""),
("SOC-DET-118","wmi_persistence","high","T1546.003","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where FileName == "wmic.exe"
| where ProcessCommandLine has "EventConsumer" or ProcessCommandLine has "__FilterToConsumerBinding""""),
("SOC-DET-119","scheduled_task_create","medium","T1053.005","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/create"
| where ProcessCommandLine has "SYSTEM" or ProcessCommandLine has "runas" or ProcessCommandLine has "admin""""),
("SOC-DET-120","service_install","medium","T1543.003","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where ProcessCommandLine has "sc create" or ProcessCommandLine has "New-Service""""),
("SOC-DET-121","defender_tamper","critical","T1562.001","DeviceEvents","MDE",
 """DeviceEvents | where TimeGenerated > ago(1d)
| where ActionType in ("TamperProtectionDisable","AntivirusDetectionDisabled","CodeInjectionDisable")""""),
("SOC-DET-122","asr_rule_block","high","T1562.001","DeviceEvents","MDE",
 """DeviceEvents | where TimeGenerated > ago(1d)
| where ActionType contains "Asr" and ActionType contains "Block"
| project TimeGenerated, DeviceName, ActionType, FileName, InitiatingProcessCommandLine""""),
("SOC-DET-123","credential_dump_tools","critical","T1003","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(1d)
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","procdump","lsass.exe","comsvcs.dll")""""),
("SOC-DET-124","c2_beaconing","high","T1071","DeviceNetworkEvents","MDE",
 """DeviceNetworkEvents | where TimeGenerated > ago(1d)
| where RemotePort == 443
| summarize Connections = count(), Processes = dcount(InitiatingProcessFileName) by DeviceName, RemoteIP
| where Connections between (20 .. 2000) and Processes > 2"""),
("SOC-DET-125","rare_process_on_dc","high","T1068","DeviceProcessEvents","MDE",
 """DeviceProcessEvents | where TimeGenerated > ago(2d)
| where DeviceName has "dc"
| where FileName has_any ("psexec.exe","mimikatz.exe","kerberoast","procdump.exe")""""),
("SOC-DET-126","usb_device_insert","medium","T1091","DeviceEvents","MDE",
 """DeviceEvents | where TimeGenerated > ago(1d)
| where ActionType == "PnpDeviceConnected" | where AdditionalFields has "USB"""",),
("SOC-DET-127","mass_file_deletion","high","T1485","DeviceFileEvents","MDE",
 """DeviceFileEvents | where TimeGenerated > ago(15m)
| where ActionType == "FileDeleted"
| summarize Deletions = count() by DeviceName, bin(TimeGenerated, 5m)
| where Deletions > 100"""),
("SOC-DET-128","office_spawns_script","high","T1566.001","DeviceProcessEvents","MDE",
 """let office = DeviceProcessEvents | where FileName in ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE")
    | project TimeGenerated, DeviceId, OfficeFile = FileName;
DeviceProcessEvents | join kind=inner office on DeviceId
| where TimeGenerated between (office_TimeGenerated .. (office_TimeGenerated + 2m))
| where FileName in ("powershell.exe","cmd.exe","wscript.exe","cscript.exe")""""),
# ---- NETWORK (Firewall/VPN/WAF/DNS) ----
("SOC-DET-129","port_scan","low","T1046","CommonSecurityLog","Firewall",
 """CommonSecurityLog | where TimeGenerated > ago(15m)
| where DeviceAction == "deny"
| summarize Denies = count(), Ports = dcount(DestinationPort) by SourceIP, bin(TimeGenerated, 5m)
| where Ports > 20"""),
("SOC-DET-130","wap_credential_stuffing","medium","T1110.004","CommonSecurityLog","WAF",
 """CommonSecurityLog | where TimeGenerated > ago(15m)
| where DeviceEventClassID has "auth" or DeviceEventClassID has "401"
| where DeviceAction == "fail" or DeviceAction == "drop"
| summarize Attempts = count() by SourceIP, bin(TimeGenerated, 5m) | where Attempts > 20"""),
("SOC-DET-131","vpn_impossible_travel","high","T1078","CommonSecurityLog","VPN",
 """CommonSecurityLog | where DeviceProduct == "PAN-OS" or DeviceEventClassID has "globalprotect"
| where Activity == "globalprotect-login-success"
| extend User = coalesce(SourceUserID, SourceUserName, "unknown")
| summarize IPs = dcount(SourceIP), Countries = dcount_if(DeviceCountry, isnotempty(DeviceCountry))
    by User, bin(TimeGenerated, 1d) | where IPs > 3 or Countries > 2"""),
("SOC-DET-132","dns_tunneling","medium","T1071.004","DnsEvents","DNS",
 """DnsEvents | where TimeGenerated > ago(15m)
| where Name !endswith ".internal" | where Name !endswith ".local"
| summarize Queries = count(), UniqueNames = dcount(Name) by ClientIP, bin(TimeGenerated, 5m)
| where UniqueNames > 50"""),
("SOC-DET-133","outbound_exfil_spike","high","T1048","CommonSecurityLog","Firewall",
 """CommonSecurityLog | where TimeGenerated > ago(30m)
| where DeviceDirection == "1" | where DeviceAction == "allow"
| summarize Bytes = sum(SentBytes) by DestinationIP, bin(TimeGenerated, 5m)
| where Bytes > 500000000"""),
("SOC-DET-134","traffic_to_threat_intel","high","T1071","CommonSecurityLog","Firewall",
 """let bad = externaldata(IP: string) [@"https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"]
    with (format="txt");
CommonSecurityLog | where SourceIP in (bad) or DestinationIP in (bad)
| where TimeGenerated > ago(1h)"""),
# ---- AWS ----
("SOC-DET-135","guardduty_crypto","critical","T1486","AWS_GuardDuty","GuardDuty",
 """AWS_GuardDuty | where TimeGenerated > ago(1d) | where Severity >= 7
| where Title has_any ("Cryptocurrency","UnauthorizedAccess","PrivilegeEscalation")""""),
("SOC-DET-136","s3_bucket_public","high","T1530","AWSCloudTrail","CloudTrail",
 """AWSCloudTrail | where TimeGenerated > ago(1d)
| where EventName in ("PutBucketAcl","PutBucketPolicy")
| where RequestParameters has "AllUsers" or RequestParameters has "authenticated" """,),
("SOC-DET-137","iam_role_escalation","high","T1098","AWSCloudTrail","CloudTrail",
 """AWSCloudTrail | where TimeGenerated > ago(1d)
| where EventName in ("AttachUserPolicy","AttachRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion")
| where UserIdentityType == "IAMUser" or UserIdentityType == "AssumedRole""""),
("SOC-DET-138","root_account_login","critical","T1078.004","AWSCloudTrail","CloudTrail",
 """AWSCloudTrail | where TimeGenerated > ago(1d)
| where EventName == "ConsoleLogin" | where UserIdentityType == "Root"
| where ResponseElements has "Success"""",),
("SOC-DET-139","security_group_open","high","T1562.007","AWSCloudTrail","CloudTrail",
 """AWSCloudTrail | where TimeGenerated > ago(1d)
| where EventName in ("AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress")
| where RequestParameters has "0.0.0.0/0" """,),
# ---- AZURE ----
("SOC-DET-140","nsg_rdp_ssh_bruteforce","medium","T1110","AzureNetworkAnalytics_CL","NSG",
 """AzureNetworkAnalytics_CL | where TimeGenerated > ago(1d)
| where AllowedOut_F == true and DestinationPort_F in (22, 3389, 5985)
| summarize Attempts = count() by DestinationIP_s, DestinationPort_F, bin(TimeGenerated, 15m)
| where Attempts > 50"""),
("SOC-DET-141","azure_privileged_change","high","T1078.004","AzureActivity","Azure",
 """AzureActivity | where TimeGenerated > ago(1d)
| where OperationNameValue has_any ("roleAssignments/write","Microsoft.Authorization",
    "Microsoft.Security/policies/write","Microsoft.Sql/servers/firewallRules/write")""""),
("SOC-DET-142","keyvault_purge","critical","T1485","AzureDiagnostics","Key Vault",
 """AzureDiagnostics | where TimeGenerated > ago(1d)
| where OperationName == "SecretPurge" or OperationName == "KeyPurge"
| where ResultType == "Success"""",),
("SOC-DET-143","storage_key_listed","high","T1552.004","AzureActivity","Storage",
 """AzureActivity | where TimeGenerated > ago(1d)
| where OperationNameValue has "listKeys" | where ActivityStatus == "Succeeded"
| where CallerIpAddress !in ("<TRUSTED_SOC_IP>")""""),
("SOC-DET-144","logicapp_modified","high","T1078","AzureActivity","Logic Apps",
 """AzureActivity | where TimeGenerated > ago(1d)
| where OperationNameValue has "Microsoft.Logic/workflows" and OperationNameValue has "write"
| where ActivityStatus == "Accepted"""",),
# ---- GCP ----
("SOC-DET-145","gcp_iam_policy_change","high","T1098","GCPAuditLogs","GCP",
 """GCPAuditLogs | where TimeGenerated > ago(1d)
| where methodName has_any ("SetIamPolicy","CreateRole","UpdateRole","GrantRole")""""),
("SOC-DET-146","gcp_sa_key_created","high","T1098","GCPAuditLogs","GCP",
 """GCPAuditLogs | where TimeGenerated > ago(1d)
| where methodName == "google.iam.admin.v1.CreateServiceAccountKey"
| where resource.type == "service_account"""",),
("SOC-DET-147","gcp_bucket_public","high","T1530","GCPAuditLogs","GCP",
 """GCPAuditLogs | where TimeGenerated > ago(1d)
| where methodName has "SetIamPolicy"
| where resource.labels has "storage.googleapis.com"
| where protoPayload has "allUsers" or protoPayload has "allAuthenticatedUsers""""),
# ---- M365 / SharePoint ----
("SOC-DET-148","sharepoint_bulk_download","critical","T1567.002","OfficeActivity","SharePoint",
 """OfficeActivity | where RecordType == 6
| where Operation in ("FileDownloaded","FilePreviewed","FileAccessed")
| extend FileSizeMB = FileSizeBytes / 1048576.0
| summarize Downloads = count(), TotalMB = sum(FileSizeMB) by UserId, ClientIP, bin(TimeGenerated, 5m)
| where Downloads > 100 or TotalMB > 100"""),
("SOC-DET-149","sharepoint_external_sharing","high","T1530","OfficeActivity","SharePoint",
 """OfficeActivity | where TimeGenerated > ago(1d)
| where Operation == "SharingSet" | where ExternalAccess == true
| where SharingType in ("AnonymousLink","CompanyLink") or Recipients has "@" and Recipients !endswith "@<YOUR_DOMAIN>""""),
("SOC-DET-150","sensitive_file_sync","high","T1530","OfficeActivity","OneDrive",
 """OfficeActivity | where TimeGenerated > ago(1d)
| where Operation == "SyncItem"
| where SourceRelativeUrl has_any ("confidential","secret","finance","salary","hr")
    or SensitivityLabel contains "Confidential""""),
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="rules")
    args = p.parse_args()
    out = Path(args.out); out.mkdir(exist_ok=True)
    manifest = []
    for rid, name, sev, mitre, table, source, query in RULES:
        tactic = mitre.split(".")[0]
        header = (f"// METADATA-START\n// id: {rid} | name: {name} | severity: {sev}\n"
                  f"// mitre: {mitre} | nist: DE.CM-7 | iso27001: A.8.16 | soc2: CC7.2\n"
                  f"// data_source: {source} | table: {table}\n// METADATA-END\n")
        (out / f"{rid}_{name}.kql").write_text(header + query + "\n")
        manifest.append({"id": rid, "name": name, "severity": sev, "tactics": [tactic],
                         "query": query, "table": table, "source": source})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Generated {len(RULES)} rules -> {out}/")

if __name__ == "__main__":
    main()
