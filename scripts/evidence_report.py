#!/usr/bin/env python3

"""Map detection rules to SOC 2, ISO 27001 and NIS2 controls."""

import argparse
import datetime
import json
from pathlib import Path


CONTROL_MAP = {
    "soc2:CC6.1": [
        "admin_added",
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
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--rules",
        required=True,
    )

    parser.add_argument(
        "--out",
        default="evidence/controls.json",
    )

    args = parser.parse_args()

    manifest = json.loads(
        Path(args.rules).read_text(
            encoding="utf-8"
        )
    )

    rules = manifest["rules"]

    coverage = {}

    for control, keywords in CONTROL_MAP.items():
        hits = [
            f"{rule['id']}_{rule['name']}"
            for rule in rules
            if any(
                keyword in rule["name"]
                for keyword in keywords
            )
        ]

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

    output = Path(args.out)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    covered = sum(
        1
        for value in coverage.values()
        if value["status"] == "COVERED"
    )

    print(
        f"Coverage: {covered}/{len(coverage)} controls"
    )

    if report["gaps"]:
        print(
            "GAPS:",
            ", ".join(report["gaps"]),
        )


if __name__ == "__main__":
    main()
