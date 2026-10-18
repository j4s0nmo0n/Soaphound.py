"""Unit tests for the collection duration formatter.

_format_duration backs the end-of-run summary that main() prints inside
its try/finally. The formatter switches ranges at exactly 60s and 3600s;
the negative-value branch exists so a time.monotonic() glitch cannot
produce a nonsensical "-0.5s" summary line.
"""
import pytest

from soaphound.soaphound import _format_duration


@pytest.mark.parametrize("seconds,expected", [
    (0, "0.0s"),
    (0.4, "0.4s"),
    (12.7, "12.7s"),
    (59.9, "59.9s"),
    (60, "1m 0s"),
    (61, "1m 1s"),
    (125, "2m 5s"),
    (3599, "59m 59s"),
    (3600, "1h 0m 0s"),
    (3661, "1h 1m 1s"),
    (7325, "2h 2m 5s"),
])
def test_format_duration(seconds, expected):
    assert _format_duration(seconds) == expected


def test_format_duration_negative_clamped():
    assert _format_duration(-1.0) == "0.0s"
