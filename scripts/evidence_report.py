#!/usr/bin/env python3
"""Map deployed detection rules to compliance controls -> evidence/controls.json"""
import json, sys, datetime
from pathlib import Path

CONTROL_MAP = {  # control -> rule name keywords
    "soc2:CC6.1":  ["admin_added", "privileged_role", "guest_added"],
    "soc2:CC7.2":  ["impossible_travel", "bruteforce", "risky_signin", "password_spray",
                    "token_replay", "port_scan", "credential_stuffing", "dns_tunneling",
                    "beacon", "crypto", "bulk_download", "external_sharing", "sync"],
    "soc2:CC7.3":  ["account_reenabled", "tamper", "asr", "mailbox_forwarding"],
    "soc2:CC7.5":  ["known_exploited", "vulnerability"],
    "iso27001:A.8.8":   ["known_exploited"],
    "iso27001:A.8.16":  ["impossible_travel", "bruteforce", "beacon", "port_scan", "bulk_download"],
    "iso27001:A.8.23":  ["wap_credential", "dns_tunneling", "traffic_to_threat_intel"],
    "nis2:21(2)":   ["impossible_travel", "bruteforce", "tamper", "crypto", "iam_escalation", "root_account"],
}

def main():
    manifest = json.loads(Path(sys.argv[sys.argv.index("--rules")+1]).read_text())
    out = Path(sys.argv[sys.argv.index("--out")+1] if "--out" in sys.argv else "evidence/controls.json")
    coverage = {}
    for control, keywords in CONTROL_MAP.items():
        hits = [r["id"] + "_" + r["name"] for r in manifest
                if any(k in r["name"] for k in keywords)]
        coverage[control] = {"rule_count": len(hits), "rules": hits,
                             "status": "COVERED" if hits else "GAP"}
    report = {"generated": datetime.datetime.utcnow().isoformat(),
              "total_rules": len(manifest),
              "controls": coverage,
              "gaps": [c for c, v in coverage.items() if v["status"] == "GAP"]}
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"Coverage: {sum(1 for c in coverage.values() if c['status']=='COVERED')}/{len(coverage)} controls")
    if report["gaps"]: print("GAPS:", ", ".join(report["gaps"]))

if __name__ == "__main__":
    main()
