"""Unit tests for the GPO SYSVOL privilege rights tracker.

Covers:
    * _TRACKED_PRIVRIGHTS keeps the lowercase canonical form expected by
      the GptTmpl.inf parser.
    * SeAssignPrimaryTokenPrivilege is tracked alongside SeImpersonatePrivilege
      -- both form the classic token-duplication escalation pair.
"""
from soaphound.ad.collectors.gpo_sysvol import _TRACKED_PRIVRIGHTS


class TestTrackedPrivRights:
    def test_assign_primary_token_privilege_tracked(self):
        assert "seassignprimarytokenprivilege" in _TRACKED_PRIVRIGHTS

    def test_impersonate_privilege_still_tracked(self):
        # Guard: the token escalation pair must stay together.
        assert "seimpersonateprivilege" in _TRACKED_PRIVRIGHTS

    def test_all_entries_are_lowercase(self):
        # The GptTmpl.inf parser normalises keys via .lower() before
        # membership test, so entries must already be lowercase.
        for entry in _TRACKED_PRIVRIGHTS:
            assert entry == entry.lower(), entry

    def test_core_offensive_privileges_present(self):
        expected = {
            "sedebugprivilege",
            "seimpersonateprivilege",
            "seassignprimarytokenprivilege",
            "setcbprivilege",
            "sebackupprivilege",
            "serestoreprivilege",
            "setakeownershipprivilege",
            "seloaddriverprivilege",
        }
        missing = expected - _TRACKED_PRIVRIGHTS
        assert not missing, f"missing offensive privileges: {sorted(missing)}"
