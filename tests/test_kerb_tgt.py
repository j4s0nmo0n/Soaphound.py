"""Tests for ``soaphound.adcs.kerb_tgt`` and its wiring into the WS-Trust dispatch.

The AS-REQ itself is mocked — the goal is to pin down the contract:
``KRB5CCNAME`` is set to a FILE: path pointing inside an auto-cleaned
``TemporaryDirectory`` while the ``with`` block runs, and the previous
value (if any) is restored on exit. The dispatch in ``soaphound.main``
must use the context when CLI creds are provided and ``nullcontext`` when
they are not.
"""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from soaphound import soaphound as soaphound_mod
from soaphound.adcs import kerb_tgt


class _FakeKey:
    """Minimal stand-in for impacket's Key / session_key objects."""


def _fake_get_tgt(user_principal, password, domain, lm, nt, aes, kdcHost=None):
    return b"TGT_BLOB", object(), _FakeKey(), _FakeKey()


@contextlib.contextmanager
def _patched_ccache():
    """Patch impacket's CCache and getKerberosTGT to avoid network IO."""
    with patch.object(kerb_tgt, "getKerberosTGT", side_effect=_fake_get_tgt), \
            patch.object(kerb_tgt, "CCache") as fake_ccache_cls:
        instance = fake_ccache_cls.return_value
        instance.fromTGT = lambda *a, **kw: None

        def _write_empty(path):
            Path(path).write_bytes(b"")

        instance.saveFile = _write_empty
        yield fake_ccache_cls


def test_inline_tgt_ccache_sets_env_and_restores_it(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ) as ccache_path:
            assert os.environ["KRB5CCNAME"] == f"FILE:{ccache_path}"
            assert Path(ccache_path).exists()
    assert "KRB5CCNAME" not in os.environ


def test_inline_tgt_ccache_restores_previous_env(monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/original.ccache")
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ):
            assert os.environ["KRB5CCNAME"].startswith("FILE:")
            assert os.environ["KRB5CCNAME"] != "FILE:/tmp/original.ccache"
    assert os.environ["KRB5CCNAME"] == "FILE:/tmp/original.ccache"


def test_inline_tgt_ccache_cleanup_tempdir(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    saved_path = {}
    with _patched_ccache():
        with kerb_tgt.inline_tgt_ccache(
            username="yuji", domain="jjk.local", password="P@ssword!"
        ) as ccache_path:
            saved_path["p"] = ccache_path
            assert Path(ccache_path).exists()
            assert "soaphound-krb-" in ccache_path
    # tempdir destroyed on context exit
    assert not Path(saved_path["p"]).exists()
    assert not Path(saved_path["p"]).parent.exists()


def test_inline_tgt_ccache_requires_a_secret():
    with pytest.raises(ValueError):
        with kerb_tgt.inline_tgt_ccache(username="yuji", domain="jjk.local"):
            pass


def test_inline_tgt_ccache_parses_hashes_and_aes(monkeypatch):
    """nt_hash / aes_key are passed through to getKerberosTGT verbatim."""
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    captured = {}

    def spy(user_principal, password, domain, lm, nt, aes, kdcHost=None):
        captured.update(dict(
            password=password, lm=lm, nt=nt, aes=aes, kdc=kdcHost,
        ))
        return b"TGT", object(), _FakeKey(), _FakeKey()

    with patch.object(kerb_tgt, "getKerberosTGT", side_effect=spy), \
            patch.object(kerb_tgt, "CCache") as fake_ccache_cls:
        fake_ccache_cls.return_value.fromTGT = lambda *a, **kw: None
        fake_ccache_cls.return_value.saveFile = lambda p: Path(p).write_bytes(b"")
        with kerb_tgt.inline_tgt_ccache(
            username="yuji",
            domain="jjk.local",
            nt_hash="aad3b435b51404eeaad3b435b51404ee",
            lm_hash="aad3b435b51404eeaad3b435b51404ee",
            aes_key="deadbeef" * 8,
            kdc_ip="192.168.56.101",
        ):
            pass

    assert captured["password"] == ""
    assert captured["nt"] == "aad3b435b51404eeaad3b435b51404ee"
    assert captured["lm"] == "aad3b435b51404eeaad3b435b51404ee"
    assert captured["aes"] == "deadbeef" * 8
    assert captured["kdc"] == "192.168.56.101"


# ---------------------------------------------------------------------------
# Dispatch wiring in soaphound.main
# ---------------------------------------------------------------------------


def _base_namespace(**overrides):
    ns = argparse.Namespace(
        collectionmethod="Default",
        ts=False,
        v=False,
        kerberos=False,
        username=None,
        password=None,
        hashes=None,
        aes_key=None,
        kdc_ip=None,
        domain=None,
        domain_controller="dc.example.local",
        list_policies_ws=False,
        enroll_ws=False,
        cep_url=None,
        ces_url=None,
        wstep_ca=None,
        wstep_template=None,
        wstep_upn=None,
        wstep_out=None,
        insecure_ssl=False,
        user_agent=None,
        auth_dc=None,
        adcap_get_forest=False,
        adcap_translate=None,
        adcap_change_feature=None,
        adcap_change_feature_dn=None,
        cert_find=False,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def test_dispatch_uses_inline_tgt_when_creds_provided(monkeypatch):
    ns = _base_namespace(
        enroll_ws=True,
        username="yuji",
        password="P@ssword!",
        domain="jjk.local",
    )
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    calls = {"inline": 0, "kwargs": None}

    @contextlib.contextmanager
    def fake_inline(**kw):
        calls["inline"] += 1
        calls["kwargs"] = kw
        yield "/fake/ccache"

    from soaphound.adcs import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    soaphound_mod.main()

    assert calls["inline"] == 1
    assert calls["kwargs"]["username"] == "yuji"
    assert calls["kwargs"]["password"] == "P@ssword!"
    assert calls["kwargs"]["domain"] == "jjk.local"
    # No -k and no explicit --kdc-ip, so the DC is used as KDC fallback.
    assert calls["kwargs"]["kdc_ip"] == "dc.example.local"


def test_dispatch_parses_hashes_LMNT(monkeypatch):
    ns = _base_namespace(
        enroll_ws=True,
        username="yuji",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        domain="jjk.local",
    )
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    seen = {}

    @contextlib.contextmanager
    def fake_inline(**kw):
        seen.update(kw)
        yield "/fake"

    from soaphound.adcs import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    soaphound_mod.main()

    assert seen["lm_hash"] == "aad3b435b51404eeaad3b435b51404ee"
    assert seen["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_dispatch_parses_hashes_NT_only(monkeypatch):
    ns = _base_namespace(
        enroll_ws=True,
        username="yuji",
        hashes="31d6cfe0d16ae931b73c59d7e0c089c0",
        domain="jjk.local",
    )
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    seen = {}

    @contextlib.contextmanager
    def fake_inline(**kw):
        seen.update(kw)
        yield "/fake"

    from soaphound.adcs import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    soaphound_mod.main()

    assert seen["lm_hash"] is None
    assert seen["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_dispatch_falls_back_to_system_ccache_without_creds(monkeypatch):
    ns = _base_namespace(enroll_ws=True)  # no -u/-p/--hashes/--aes-key
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.wstep as wstep_mod
    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)

    called = {"n": 0}

    @contextlib.contextmanager
    def fake_inline(**kw):
        called["n"] += 1
        yield "/should/not/be/used"

    from soaphound.adcs import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    soaphound_mod.main()
    assert called["n"] == 0


def test_dispatch_uses_inline_tgt_for_list_policies(monkeypatch):
    ns = _base_namespace(
        list_policies_ws=True,
        username="yuji",
        password="P@ssword!",
        domain="jjk.local",
    )
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.xcep as xcep_mod
    monkeypatch.setattr(xcep_mod, "run_list_policies", lambda **_: None)

    called = {"n": 0}

    @contextlib.contextmanager
    def fake_inline(**kw):
        called["n"] += 1
        yield "/fake"

    from soaphound.adcs import kerb_tgt as kerb_tgt_mod
    monkeypatch.setattr(kerb_tgt_mod, "inline_tgt_ccache", fake_inline)

    soaphound_mod.main()
    assert called["n"] == 1
