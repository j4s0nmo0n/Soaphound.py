"""Unit tests for the trust flag decoder and posture classifier.

Covers:
    * _TRUST_FLAGS now includes USES_AES_KEYS (0x100) per MS-ADTS 6.1.6.7.9.
    * _decode_flag_names splits combined bitfields correctly.
    * _classify_trust_posture derives BloodHound-canonical labels from
      trustType + trustAttributes + DNS relationship between the collecting
      domain and the trust partner.
"""
import pytest

from soaphound.ad.collectors.trust import (
    _TRUST_FLAGS,
    _classify_trust_posture,
    _decode_flag_names,
    _dns_relation,
)


class TestTrustFlags:
    def test_uses_aes_keys_present(self):
        assert _TRUST_FLAGS.get("USES_AES_KEYS") == 0x100

    def test_decode_single_aes_flag(self):
        assert _decode_flag_names(0x100) == ["USES_AES_KEYS"]

    def test_decode_rc4_and_aes_combined(self):
        names = _decode_flag_names(0x180)
        assert set(names) == {"USES_RC4_ENCRYPTION", "USES_AES_KEYS"}

    def test_decode_zero_returns_empty(self):
        assert _decode_flag_names(0) == []

    def test_all_twelve_flags_decoded_when_all_set(self):
        all_bits = 0
        for bit in _TRUST_FLAGS.values():
            all_bits |= bit
        names = _decode_flag_names(all_bits)
        assert set(names) == set(_TRUST_FLAGS.keys())
        assert len(_TRUST_FLAGS) == 12


class TestDnsRelation:
    @pytest.mark.parametrize("self_domain, partner, expected", [
        ("jjk.local", "sub.jjk.local", "parent-child"),
        ("sub.jjk.local", "jjk.local", "parent-child"),
        ("jjk.local", "a.b.c.jjk.local", "shortcut"),
        ("a.b.jjk.local", "c.d.jjk.local", "shortcut"),
        ("jjk.local", "other-tree.local", "unrelated"),
        ("jjk.local", "other-forest.corp", "unrelated"),
        ("jjk.local", "", "unrelated"),
        ("", "jjk.local", "unrelated"),
    ])
    def test_dns_relation_cases(self, self_domain, partner, expected):
        assert _dns_relation(self_domain, partner) == expected


class TestClassifyTrustPosture:
    """Table of cases from the audit spec, collecting domain `jjk.local`
    unless the partner is a parent (then the collector is sub.jjk.local)."""

    @pytest.mark.parametrize("trust_type, trust_attrs, self_domain, partner, expected", [
        # trustType=2 (UPLEVEL) + WITHIN_FOREST + direct child
        (2, 0x28, "jjk.local", "sub.jjk.local", "ParentChild"),
        # trustType=2 + WITHIN_FOREST + direct parent (collector is child)
        (2, 0x20, "sub.jjk.local", "jjk.local", "ParentChild"),
        # trustType=2 + WITHIN_FOREST + non-adjacent same-forest
        (2, 0x20, "jjk.local", "a.b.c.jjk.local", "Shortcut"),
        # trustType=2 + WITHIN_FOREST + DNS unrelated (separate tree same forest)
        (2, 0x20, "jjk.local", "other-tree.local", "TreeRoot"),
        # trustType=2 + FOREST_TRANSITIVE, no WITHIN_FOREST
        (2, 0x8, "jjk.local", "other-forest.local", "Forest"),
        # trustType=2 + no relevant flags
        (2, 0, "jjk.local", "external.local", "External"),
        # trustType=3 => MIT realm, flags irrelevant
        (3, 0, "jjk.local", "MIT.LOCAL", "MIT"),
        # trustType=4 => DCE
        (4, 0, "jjk.local", "legacy.local", "DCE"),
        # trustType=1 => NT4 downlevel
        (1, 0, "jjk.local", "nt4-domain", "DOWNLEVEL"),
    ])
    def test_posture_table(self, trust_type, trust_attrs, self_domain, partner, expected):
        assert _classify_trust_posture(
            trust_type, trust_attrs, self_domain, partner,
        ) == expected

    def test_unknown_trust_type_falls_through(self):
        assert _classify_trust_posture(99, 0, "jjk.local", "foo.local") == "Unknown"

    def test_mit_takes_precedence_over_within_forest(self):
        # Defensive: trustType=3 wins even if a nonsensical WITHIN_FOREST is set.
        assert _classify_trust_posture(3, 0x20, "jjk.local", "MIT.LOCAL") == "MIT"
