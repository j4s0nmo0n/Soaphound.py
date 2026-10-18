"""Unit tests for the collection method preset handling.

Covers:
    * normalize_collection_method() remaps the deprecated ADWSOnly to
      Stealth and emits the deprecation warning.
    * The Stealth warning block names every collection step that will be
      skipped, so an operator cannot miss what the mode trades away.
    * should_skip_sysvol() returns True iff the preset is Stealth, so the
      SYSVOL block in soaphound.main() stays off TCP:445 in that mode.
"""
import io
from argparse import Namespace

import pytest

from soaphound.lib.collection_mode import (
    ADWS_ONLY_DEPRECATION,
    STEALTH_WARNING,
    normalize_collection_method,
    should_skip_sysvol,
)


def _opts(method):
    return Namespace(collectionmethod=method)


class TestNormalizeCollectionMethod:
    def test_default_passes_through_silent(self):
        buf = io.StringIO()
        options = _opts("Default")
        normalize_collection_method(options, stream=buf)
        assert options.collectionmethod == "Default"
        assert buf.getvalue() == ""

    def test_stealth_emits_warning_block(self):
        buf = io.StringIO()
        options = _opts("Stealth")
        normalize_collection_method(options, stream=buf)
        assert options.collectionmethod == "Stealth"
        out = buf.getvalue()
        assert "Stealth mode: ADWS only" in out
        # Deprecation line must NOT appear when the user asked for Stealth
        # directly: it is reserved for the ADWSOnly alias.
        assert "deprecated" not in out

    def test_adwsonly_is_remapped_with_deprecation_warning(self):
        buf = io.StringIO()
        options = _opts("ADWSOnly")
        normalize_collection_method(options, stream=buf)
        assert options.collectionmethod == "Stealth"
        out = buf.getvalue()
        assert ADWS_ONLY_DEPRECATION in out
        # The stealth warning block MUST also fire after the remap: the
        # user still needs to know what will be skipped.
        assert "Stealth mode: ADWS only" in out

    def test_stealth_warning_lists_all_skipped_steps(self):
        """The warning block is the only chance to catch an operator who
        expects a full output. It must name every category that will be
        missing from the collect."""
        expected_bullets = [
            "GPO settings",
            "User rights assignments",
            "Local administrators",
            "GPP cpassword",
            "Computer session enumeration",
        ]
        for bullet in expected_bullets:
            assert bullet in STEALTH_WARNING, bullet


class TestShouldSkipSysvol:
    def test_default_runs_sysvol(self):
        assert should_skip_sysvol(_opts("Default")) is False

    def test_stealth_skips_sysvol(self):
        assert should_skip_sysvol(_opts("Stealth")) is True

    def test_adwsonly_before_normalize_is_not_stealth(self):
        """should_skip_sysvol() only sees the post-normalize value in
        production. Document the pre-normalize behaviour explicitly so a
        future caller that forgets normalize_collection_method does not
        silently open SMB when the user asked for ADWSOnly."""
        assert should_skip_sysvol(_opts("ADWSOnly")) is False


class TestCliChoices:
    """Guard that the argparse 'choices' tuple stays in sync with the
    presets the collection_mode module knows about."""

    def test_cli_choices_tuple_matches(self):
        from soaphound.lib.cli import gen_cli_args as _  # noqa: F401
        import argparse
        import soaphound.lib.cli as cli_mod

        # Rebuild the parser by introspecting the function source: we can
        # just invoke it with sys.argv manipulated via monkeypatch, but
        # the simpler check is to parse a known-good invocation and a
        # known-bad one. Build a minimal parser mirroring gen_cli_args is
        # fragile, so we parse via subprocess-style with sys.argv patched.
        import sys as _sys
        old_argv = _sys.argv
        try:
            _sys.argv = ["soaphound", "-c", "Nonsense", "-u", "u", "-dc", "d"]
            with pytest.raises(SystemExit):
                cli_mod.gen_cli_args()
        finally:
            _sys.argv = old_argv

    @pytest.mark.parametrize("preset", ["Default", "Stealth", "ADWSOnly"])
    def test_cli_accepts_each_valid_preset(self, preset, monkeypatch):
        import soaphound.lib.cli as cli_mod
        monkeypatch.setattr(
            "sys.argv",
            ["soaphound", "-c", preset, "-u", "u", "-dc", "d"],
        )
        options = cli_mod.gen_cli_args()
        assert options.collectionmethod == preset
