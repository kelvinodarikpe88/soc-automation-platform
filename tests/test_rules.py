#!/usr/bin/env python3

"""CI validation for Microsoft Sentinel detection rules."""

import json
import re
from pathlib import Path


RULES = Path("rules")


def test_all_rules_have_metadata():
    missing = []

    required = [
        "METADATA-START",
        "METADATA-END",
        "// id:",
        "// name:",
        "// severity:",
        "// tactics:",
        "// techniques:",
    ]

    for file in RULES.glob("*.kql"):
        text = file.read_text(encoding="utf-8")

        if not all(item in text for item in required):
            missing.append(file.name)

    assert not missing, f"Missing metadata: {missing}"


def test_rule_ids_unique():
    ids = []

    for file in RULES.glob("*.kql"):
        text = file.read_text(encoding="utf-8")
        match = re.search(r"// id:\s*(\S+)", text)

        assert match, f"Missing rule ID: {file.name}"
        ids.append(match.group(1))

    assert len(ids) == len(set(ids)), "Duplicate rule IDs"


def test_manifest_valid():
    manifest_path = RULES / "manifest.json"

    assert manifest_path.exists(), (
        "rules/manifest.json is missing"
    )

    data = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    assert isinstance(data, dict)

    assert "rules" in data
    assert isinstance(data["rules"], list)

    assert len(data["rules"]) >= 50, (
        f"Expected >=50 rules, got {len(data['rules'])}"
    )

    for rule in data["rules"]:
        assert "id" in rule
        assert "name" in rule
        assert "severity" in rule
        assert "tactics" in rule
        assert "techniques" in rule


def test_manifest_matches_files():
    manifest = json.loads(
        (RULES / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    manifest_ids = {
        rule["id"]
        for rule in manifest["rules"]
    }

    file_ids = set()

    for file in RULES.glob("*.kql"):
        text = file.read_text(encoding="utf-8")
        match = re.search(r"// id:\s*(\S+)", text)

        assert match, f"Missing ID in {file.name}"
        file_ids.add(match.group(1))

    assert manifest_ids == file_ids


def test_queries_start_with_table():
    for file in RULES.glob("*.kql"):
        lines = [
            line
            for line in file.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
            and not line.strip().startswith("//")
        ]

        assert lines, f"{file.name}: empty query"

        assert not lines[0].startswith(
            ("|", "summarize", "where")
        ), f"{file.name}: bad query start"


def test_no_plaintext_secrets():
    files = list(RULES.glob("*.kql"))

    blob = "\n".join(
        file.read_text(encoding="utf-8")
        for file in files
    )

    assert not re.search(
        r"AKIA[0-9A-Z]{16}",
        blob,
    )

    assert not re.search(
        r"BEGIN (RSA|OPENSSH) PRIVATE KEY",
        blob,
    )
