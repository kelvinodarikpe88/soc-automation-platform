#!/usr/bin/env python3
"""Enable Sentinel data connectors via Azure Resource Manager API.
Usage: python3 enable_connectors.py --workspace rg-soc-lab law-soc --connectors AzureActiveDirectory Office365 ..."""
import argparse, json, subprocess, sys, urllib.request

def get_token():
    out = subprocess.run(["az", "account", "get-access-token", "--resource",
                          "https://management.azure.com", "--query", "accessToken",
                          "-o", "tsv"], capture_output=True, text=True, check=True)
    return out.stdout.strip()

def arm_put(url, token, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PUT")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]

CONNECTORS = {
    "AzureActiveDirectory":            "Microsoft.SecurityInsights/AzureActiveDirectory",
    "Office365":                       "Microsoft.SecurityInsights/Office365",
    "AzureActivity":                   "Microsoft.SecurityInsights/AzureActivity",
    "MicrosoftDefenderAdvancedThreatProtection": "Microsoft.SecurityInsights/MicrosoftDefenderAdvancedThreatProtection",
    "MicrosoftCloudAppSecurity":       "Microsoft.SecurityInsights/MicrosoftCloudAppSecurity",
    "MicrosoftDefenderIdentity":       "Microsoft.SecurityInsights/MicrosoftDefenderIdentity",
    "AmazonWebServicesCloudTrail":     "Microsoft.SecurityInsights/AmazonWebServicesCloudTrail",
    "ThreatIntelligence":              "Microsoft.SecurityInsights/ThreatIntelligence",
}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--subscription", required=True)
    p.add_argument("--resource-group", required=True)
    p.add_argument("--workspace", required=True)
    p.add_argument("--connectors", nargs="+", required=True)
    args = p.parse_args()
    token = get_token()
    for c in args.connectors:
        if c not in CONNECTORS:
            print(f"SKIP {c}: not in catalog"); continue
        url = (f"https://management.azure.com/subscriptions/{args.subscription}/"
               f"resourceGroups/{args.resource_group}/providers/"
               f"Microsoft.OperationalInsights/workspaces/{args.workspace}/providers/"
               f"Microsoft.SecurityInsights/dataConnectors/{CONNECTORS[c]}?api-version=2023-02-01")
        status, body = arm_put(url, token, {"kind": "AzureActiveDirectory",
                                            "properties": {"tenantId": "<TENANT_ID>"}})
        print(f"{c}: HTTP {status}")

if __name__ == "__main__":
    main()

