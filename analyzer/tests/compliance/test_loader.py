from unittest.mock import patch

import pytest

from src.compliance.loader import load_custom_ruleset, load_ruleset


def test_loads_cis_ruleset():
    rules = load_ruleset("cis")
    assert len(rules) >= 1
    assert all(r.framework == "cis" for r in rules)


def test_loads_hipaa_ruleset():
    rules = load_ruleset("hipaa")
    assert len(rules) >= 1
    assert all(r.framework == "hipaa" for r in rules)


def test_loads_pci_dss_ruleset():
    rules = load_ruleset("pci_dss")
    assert len(rules) >= 1
    assert all(r.framework == "pci_dss" for r in rules)


def test_unknown_framework_raises():
    with pytest.raises(ValueError, match="Unknown compliance framework"):
        load_ruleset("nonexistent")


def test_loads_valid_custom_ruleset():
    raw = b"""
    [
      {
        "framework": "custom",
        "rule_id": "CUSTOM-1",
        "description": "No ingress from staging CIDR to prod",
        "matcher": { "source": "192.168.100.0/24" },
        "severity": "medium"
      }
    ]
    """
    rules = load_custom_ruleset(raw)
    assert len(rules) == 1
    assert rules[0].rule_id == "CUSTOM-1"


def test_rejects_malformed_custom_ruleset():
    with pytest.raises(ValueError):
        load_custom_ruleset(b"not valid json [[[")


def test_rejects_custom_ruleset_that_is_not_a_json_array():
    with pytest.raises(ValueError, match="must be a JSON array"):
        load_custom_ruleset(b'{"framework": "custom"}')


def test_load_ruleset_reads_the_file_only_once_across_repeated_calls():
    # lru_cache is process-wide, so any fake data cached here must be
    # cleared afterward or later tests in the same session (which expect
    # the real bundled ruleset) would see this test's stale fake entry.
    load_ruleset.cache_clear()
    try:
        with patch("pathlib.Path.read_text", wraps=None) as mock_read:
            mock_read.return_value = '[{"framework": "cis", "rule_id": "X", "description": "d", "matcher": {}, "severity": "low"}]'
            load_ruleset("cis")
            load_ruleset("cis")
            assert mock_read.call_count == 1
    finally:
        load_ruleset.cache_clear()
