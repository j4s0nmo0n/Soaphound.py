"""Unit tests for the invalid-attribute retry loop in pull_all_ad_objects().

When the DC rejects a requested attribute (ADWSInvalidPropertyError -- most
often a stale LAPS attribute advertised by the embedded/fallback schema map but
not actually present in the target domain), pull_all_ad_objects() drops that one
attribute and retries, rather than aborting the whole collection.

These tests inject a MagicMock ADWSConnect pull client via the
``adws_pull_client`` argument so no real TCP:9389 connection or SPNEGO
handshake occurs; pull_client.pull is scripted with side_effect to raise on the
first call and return a valid (empty) result root on the retry.
"""
import unittest
from unittest.mock import MagicMock

from soaphound.ad.adws import ADWSInvalidPropertyError
from soaphound.ad.cache_gen import pull_all_ad_objects


# A "valid root" for pull_all_ad_objects is any iterable of element nodes; an
# empty list exercises the success path (the per-object parse loop simply does
# not run) and lets the function return its normal result dict.
_EMPTY_ROOT: list = []

_BASE_DN = "DC=example,DC=local"
_QUERY = "(objectClass=computer)"


class PullRetryTests(unittest.TestCase):
    def test_retry_drops_rejected_attribute(self):
        """First pull raises for ms-Mcs-AdmPwd, retry succeeds: the second
        pull must be issued without the dropped attribute, and the call must
        ultimately return the successful result."""
        pull_client = MagicMock()
        pull_client.pull.side_effect = [
            ADWSInvalidPropertyError("ms-Mcs-AdmPwd", "Sorting or Selection Property is invalid."),
            _EMPTY_ROOT,
        ]

        result = pull_all_ad_objects(
            adws_pull_client=pull_client,
            query=_QUERY,
            attributes=["sAMAccountName", "ms-Mcs-AdmPwd"],
            base_dn_override=_BASE_DN,
        )

        # (a) The retry fired, and the second request dropped the bad attribute.
        self.assertEqual(pull_client.pull.call_count, 2)
        retry_attributes = pull_client.pull.call_args_list[1].kwargs["attributes"]
        self.assertEqual(retry_attributes, ["sAMAccountName"])
        self.assertNotIn("ms-Mcs-AdmPwd", retry_attributes)

        self.assertEqual(result["objects"], [])
        self.assertEqual(result["effective_base_dn_used"], _BASE_DN)

    def test_caller_attribute_list_not_mutated(self):
        """(b) Dropping the offending attribute must not leak back into the
        list object the caller passed in."""
        pull_client = MagicMock()
        pull_client.pull.side_effect = [
            ADWSInvalidPropertyError("ms-Mcs-AdmPwd", "..."),
            _EMPTY_ROOT,
        ]

        caller_attributes = ["sAMAccountName", "ms-Mcs-AdmPwd"]
        pull_all_ad_objects(
            adws_pull_client=pull_client,
            query=_QUERY,
            attributes=caller_attributes,
            base_dn_override=_BASE_DN,
        )

        self.assertEqual(caller_attributes, ["sAMAccountName", "ms-Mcs-AdmPwd"])

    def test_last_remaining_attribute_reraises(self):
        """(c) When the rejected attribute is the only one left, there is
        nothing to fall back to: re-raise instead of looping forever."""
        pull_client = MagicMock()
        pull_client.pull.side_effect = ADWSInvalidPropertyError("ms-Mcs-AdmPwd", "...")

        with self.assertRaises(ADWSInvalidPropertyError):
            pull_all_ad_objects(
                adws_pull_client=pull_client,
                query=_QUERY,
                attributes=["ms-Mcs-AdmPwd"],
                base_dn_override=_BASE_DN,
            )

        # Raised on the first (and only) attempt -- no retry loop.
        self.assertEqual(pull_client.pull.call_count, 1)


if __name__ == "__main__":
    unittest.main()
