# Data Connector Matrix

| # | Source | Sentinel connector | Connector ID (ARM) | Chronicle path |
|---|---|---|---|---|
| 1 | Entra ID (Sign-in/Audit/Risk) | Azure Active Directory | AzureActiveDirectory | Google Workspace + Entra via forwarder → UDM |
| 2 | Defender XDR (E5) | Microsoft Defender XDR | MicrosoftDefenderAdvancedThreatProtection | — |
| 3 | Defender for Cloud Apps | MCAS | MicrosoftCloudSecurity | — |
| 4 | Office 365 (Exchange/SPO/Teams) | Office 365 | Office365 | — |
| 5 | Azure Activity | Azure Activity | AzureActivity | — |
| 6 | Defender for Identity | MDI | MicrosoftDefenderIdentity | — |
| 7 | AWS CloudTrail/GuardDuty | AWS | AmazonWebServicesCloudTrail | AWS forwarder → UDM |
| 8 | GCP audit | GCP (custom) | GCP | Native: GCP → Chronicle forwarder |
| 9 | Okta | Custom (`okta_collector.py`) | HTTP Data Collector → Okta_CL | Okta forwarder → UDM |
| 10 | Firewall/VPN (CEF) | CEF via AMA | CEF (DCR) | Syslog forwarder → UDM |
| 11 | Sysmon | Windows Security Events (AMA) | SecurityEvents | Syslog/WinEvent forwarder |
| 12 | DNS | DNS (AMA) | Dns | — |
| 13 | Threat Intel feeds | TI (TAXII/upload) | ThreatIntelligence | TI integrations |
| 14 | Azure resources (WAF, KV, Storage) | Diagnostic settings → LAW | AzureDiagnostics/WAFLogs | — |
| 15 | Microsoft Graph security alerts | Graph Security API | MicrosoftGraphSecurity | — |
