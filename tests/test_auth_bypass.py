"""Tests for the standalone-primitive auth bypass in ``soaphound.main``.

The WS-Trust enrollment primitives (--list-policies-ws / --enroll-ws)
authenticate via requests-gssapi against the system Kerberos ccache; they
do not consume the CLI credential flags. The early auth validation chain
in ``main()`` must therefore skip the "No valid authentication method"
fallback for these primitives, and keep it in place for every other
pipeline that still needs -u/-p/--hashes/-k.
"""

from __future__ import annotations

import argparse

import pytest

from soaphound import soaphound as soaphound_mod


def _base_namespace(**overrides):
    """Build a minimal argparse.Namespace that main() can traverse.

    Fields are the superset referenced by main() up to the WS-Trust
    dispatch. Overrides let individual tests toggle what matters.
    """
    ns = argparse.Namespace(
        # Logging / mode-normalization touched before the auth chain.
        collectionmethod="Default",
        ts=False,
        v=False,
        # Auth chain inputs — all empty by default so the chain is reached.
        kerberos=False,
        username=None,
        password=None,
        hashes=None,
        aes_key=None,
        kdc_ip=None,
        domain=None,
        domain_controller="dc.example.local",
        # WS-Trust dispatch flags.
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
        # Pipelines that would otherwise fire after the auth chain. Keep
        # them off so the test never reaches the collect path.
        adcap_get_forest=False,
        adcap_translate=None,
        adcap_change_feature=None,
        adcap_change_feature_dn=None,
        cert_find=False,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def _run_main_with(ns, monkeypatch):
    """Invoke main() with a crafted Namespace and WS-Trust dispatch stubbed."""
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    import soaphound.adcs.wstep as wstep_mod
    import soaphound.adcs.xcep as xcep_mod

    monkeypatch.setattr(wstep_mod, "run_enroll", lambda **_: None)
    monkeypatch.setattr(xcep_mod, "run_list_policies", lambda **_: None)

    soaphound_mod.main()


def test_enroll_ws_bypasses_auth_validation(monkeypatch):
    """--enroll-ws with no CLI creds reaches the dispatch instead of exiting."""
    ns = _base_namespace(enroll_ws=True)
    _run_main_with(ns, monkeypatch)  # must not raise SystemExit


def test_list_policies_ws_bypasses_auth_validation(monkeypatch):
    """--list-policies-ws with no CLI creds reaches the dispatch instead of exiting."""
    ns = _base_namespace(list_policies_ws=True)
    _run_main_with(ns, monkeypatch)  # must not raise SystemExit


def test_no_primitive_without_creds_still_exits(monkeypatch, caplog):
    """A non-standalone invocation without creds must keep failing closed."""
    ns = _base_namespace()  # all primitives off, no creds
    monkeypatch.setattr(soaphound_mod, "gen_cli_args", lambda: ns)

    with pytest.raises(SystemExit) as excinfo:
        soaphound_mod.main()
    assert excinfo.value.code == 1
    assert any(
        "No valid authentication method" in rec.getMessage()
        for rec in caplog.records
    )
