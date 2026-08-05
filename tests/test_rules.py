#!/usr/bin/env python3
"""CI validation: every rule has metadata, valid JSON manifest, unique IDs, no secrets."""
import json, re
from pathlib import Path

RULES = Path("rules")

def test_all_rules_have_metadata():
    missing = [f.name for f in RULES.glob("*.kql")
               if "METADATA-START" not in f.read_text() or "METADATA-END" not in f.read_text()]
    assert not missing, f"Missing metadata: {missing}"

def test_rule_ids_unique():
    ids = re.findall(r"// id: (\S+)", "\n".join(f.read_text() for f in RULES.glob("*.kql")))
    assert len(ids) == len(set(ids)), "Duplicate rule IDs"

def test_manifest_valid():
    m = json.loads((RULES / "manifest.json").read_text())
    assert len(m) >= 50, f"Expected >=50 rules, got {len(m)}"
    assert all("tactics" in r and "severity" in r for r in m)

def test_queries_start_with_table():
    for f in RULES.glob("*.kql"):
        lines = [l for l in f.read_text().splitlines() if l.strip() and not l.strip().startswith("//")]
        assert lines and not lines[0].startswith(("|", "summarize", "where")), f"{f.name}: bad query start"

def test_no_plaintext_secrets():
    blob = "\n".join(p.read_text() for p in RULES.glob("*") if p.is_file())
    assert not re.search(r"(AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH) PRIVATE KEY)", blob)
