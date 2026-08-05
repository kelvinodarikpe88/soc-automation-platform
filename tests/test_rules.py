#!/usr/bin/env python3

import json
import re
from pathlib import Path


RULES = Path("rules")


def test_all_rules_have_metadata():
    missing = []

    for file in RULES.glob("*.kql"):
        text = file.read_text(encoding="utf-8")

        required = [
            "METADATA-START",
            "METADATA-END",
            "// id:",
            "// name:",
            "// severity:",
            "// tactics:",
            "// techniques:",
        ]

        if not all(item in text for item in required):
            missing.append(file.name)

    assert not missing, f"Missing metadata: {missing}"


def test_rule_ids_unique():
    rule_files = list(RULES.glob("*.kql"))

    ids = []

    for file in rule_files:
        text = file.read_text(encoding="utf-8")

        match = re.search(
            r"^// id:\s*(\S+)",
            text,
            re.MULTILINE,
        )

        assert match, f"{file.name}: missing rule ID"

        ids.append(match.group(1))

    duplicates = sorted(
        rule_id
        for rule_id in set(ids)
        if ids.count(rule_id) > 1
    )

    assert not duplicates, (
        f"Duplicate rule IDs: {duplicates}"
    )


def test_manifest_valid():
    manifest = RULES / "manifest.json"

    assert manifest.exists(), (
        "rules/manifest.json does not exist"
    )

    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    assert isinstance(data, dict), (
        "manifest.json must contain a JSON object"
    )

    assert "rules" in data, (
        "manifest.json is missing the 'rules' field"
    )

    rules = data["rules"]

    assert isinstance(rules, list), (
        "manifest.json 'rules' must be a list"
    )

    assert len(rules) >= 50, (
        f"Expected >=50 rules, got {len(rules)}"
    )

    for rule in rules:
        assert "id" in rule, (
            f"Manifest rule missing id: {rule}"
        )

        assert "name" in rule, (
            f"Manifest rule missing name: {rule}"
        )

        assert "severity" in rule, (
            f"Manifest rule missing severity: {rule}"
        )

        assert "tactics" in rule, (
            f"Manifest rule missing tactics: {rule}"
        )

        assert "techniques" in rule, (
            f"Manifest rule missing techniques: {rule}"
        )


def test_manifest_rule_ids_unique():
    manifest = RULES / "manifest.json"

    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    rules = data["rules"]

    ids = [
        rule["id"]
        for rule in rules
    ]

    assert len(ids) == len(set(ids)), (
        "Duplicate rule IDs in manifest"
    )


def test_manifest_count_matches_rules():
    manifest = RULES / "manifest.json"

    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    rules = data["rules"]

    assert data.get("count") == len(rules), (
        f"Manifest count={data.get('count')} "
        f"but rules={len(rules)}"
    )


def test_no_plaintext_secrets():
    files = [
        path
        for path in RULES.glob("*")
        if path.is_file()
    ]

    blob = "\n".join(
        path.read_text(encoding="utf-8")
        for path in files
    )

    assert not re.search(
        r"AKIA[0-9A-Z]{16}",
        blob,
    )

    assert not re.search(
        r"BEGIN (RSA|OPENSSH) PRIVATE KEY",
        blob,
    )
