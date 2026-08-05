#!/usr/bin/env python3

import argparse
import datetime
import json
from pathlib import Path


CONTROL_MAP = {
    "soc2:CC6.1": [
        "admin_added",
        "privileged_role",
        "guest_added",
    ],
    "soc2:CC7.2": [
        "impossible_travel",
        "bruteforce",
        "risky_signin",
        "password_spray",
        "token_replay",
        "port_scan",
        "credential_stuffing",
        "dns_tunneling",
        "beacon",
        "crypto",
        "bulk_download",
        "external_sharing",
        "sync",
    ],
    "soc2:CC7.3": [
        "account_reenabled",
        "tamper",
        "asr",
        "mailbox_forwarding",
    ],
    "soc2:CC7.5": [
        "known_exploited",
        "vulnerability",
    ],
    "iso27001:A.8.8": [
        "known_exploited",
    ],
    "iso27001:A.8.16": [
        "impossible_travel",
        "bruteforce",
        "beacon",
        "port_scan",
        "bulk_download",
    ],
    "iso27001:A.8.23": [
        "dns_tunneling",
        "traffic_to_threat_intel",
    ],
    "nis2:21(2)": [
        "impossible_travel",
        "bruteforce",
        "tamper",
        "crypto",
        "iam_escalation",
        "root_account",
    ],
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate compliance evidence from rules manifest."
    )

    parser.add_argument(
        "--rules",
        required=True,
        help="Path to rules/manifest.json",
    )

    parser.add_argument(
        "--out",
        default="evidence/controls.json",
        help="Output evidence JSON path",
    )

    args = parser.parse_args()

    manifest_path = Path(args.rules)
    out = Path(args.out)

    if not manifest_path.exists():
        raise SystemExit(
            f"Manifest not found: {manifest_path}"
        )

    data = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    if isinstance(data, dict):
        rules = data.get("rules", [])
    elif isinstance(data, list):
        rules = data
    else:
        raise SystemExit(
            "Invalid manifest format."
        )

    if not isinstance(rules, list):
        raise SystemExit(
            "Manifest 'rules' field must be a list."
        )

    coverage = {}

    for control, keywords in CONTROL_MAP.items():
        hits = []

        for rule in rules:
            rule_id = str(rule.get("id", ""))
            name = str(
                rule.get(
                    "name",
                    rule.get("display_name", ""),
                )
            )

            searchable = (
                f"{rule_id} {name}"
            ).lower()

            if any(
                keyword.lower() in searchable
                for keyword in keywords
            ):
                hits.append(
                    f"{rule_id}_{name}"
                )

        coverage[control] = {
            "rule_count": len(hits),
            "rules": hits,
            "status": (
                "COVERED"
                if hits
                else "GAP"
            ),
        }

    report = {
        "generated": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "total_rules": len(rules),
        "controls": coverage,
        "gaps": [
            control
            for control, value in coverage.items()
            if value["status"] == "GAP"
        ],
    }

    out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    covered = sum(
        1
        for value in coverage.values()
        if value["status"] == "COVERED"
    )

    print(
        f"Coverage: {covered}/"
        f"{len(coverage)} controls"
    )

    if report["gaps"]:
        print(
            "GAPS:",
            ", ".join(report["gaps"]),
        )


if __name__ == "__main__":
    main()
