"""Unit tests for validation helpers in ``server.py``.

These tests cover the security-relevant pure functions: PKCE verification,
redirect-URI validation, IMAP mailbox/UID validation, header / recipient
sanitisation, ICS escaping, and RRULE construction.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib

import pytest

import server


# PKCE


def _make_pkce_pair() -> tuple[str, str]:
    verifier = "a" * 64  # within 43..128, only unreserved chars
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def test_verify_pkce_accepts_valid_s256_pair():
    verifier, challenge = _make_pkce_pair()
    assert server._verify_pkce(verifier, challenge, "S256") is True


def test_verify_pkce_rejects_plain_method():
    verifier, challenge = _make_pkce_pair()
    assert server._verify_pkce(verifier, challenge, "plain") is False


def test_verify_pkce_rejects_short_verifier():
    short = "a" * 42  # below RFC 7636 minimum of 43
    digest = hashlib.sha256(short.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert server._verify_pkce(short, challenge, "S256") is False


def test_verify_pkce_rejects_long_verifier():
    long = "a" * 129  # above RFC 7636 maximum of 128
    digest = hashlib.sha256(long.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert server._verify_pkce(long, challenge, "S256") is False


def test_verify_pkce_rejects_disallowed_characters():
    bad = "!" + "a" * 63  # ! is not in the unreserved set
    digest = hashlib.sha256(bad.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert server._verify_pkce(bad, challenge, "S256") is False


def test_verify_pkce_rejects_mismatched_challenge():
    verifier = "b" * 64
    other_digest = hashlib.sha256(b"different").digest()
    other_challenge = base64.urlsafe_b64encode(other_digest).rstrip(b"=").decode()
    assert server._verify_pkce(verifier, other_challenge, "S256") is False


# Redirect URI validation


@pytest.fixture
def no_allowlist(monkeypatch):
    monkeypatch.setattr(server, "OAUTH_REDIRECT_URIS", ())


def test_redirect_https_allowed(no_allowlist):
    ok, _ = server._validate_redirect_uri("https://example.com/cb")
    assert ok is True


def test_redirect_localhost_http_allowed(no_allowlist):
    for uri in (
        "http://localhost/cb",
        "http://127.0.0.1:8080/cb",
        "http://[::1]/cb",
    ):
        ok, _ = server._validate_redirect_uri(uri)
        assert ok is True, uri


def test_redirect_public_http_rejected(no_allowlist):
    ok, reason = server._validate_redirect_uri("http://example.com/cb")
    assert ok is False
    assert "https" in reason


def test_redirect_fragment_rejected(no_allowlist):
    ok, reason = server._validate_redirect_uri("https://example.com/cb#frag")
    assert ok is False
    assert "fragment" in reason


def test_redirect_userinfo_rejected(no_allowlist):
    ok, reason = server._validate_redirect_uri("https://attacker@example.com/cb")
    assert ok is False
    assert "userinfo" in reason


def test_redirect_userinfo_with_password_rejected(no_allowlist):
    ok, reason = server._validate_redirect_uri("https://a:b@example.com/cb")
    assert ok is False
    assert "userinfo" in reason


def test_redirect_relative_rejected(no_allowlist):
    ok, _ = server._validate_redirect_uri("/cb")
    assert ok is False


def test_redirect_empty_rejected(no_allowlist):
    ok, _ = server._validate_redirect_uri("")
    assert ok is False


def test_redirect_allowlist_enforced(monkeypatch):
    monkeypatch.setattr(
        server, "OAUTH_REDIRECT_URIS", ("https://allowed.example.com/cb",)
    )
    ok, _ = server._validate_redirect_uri("https://allowed.example.com/cb")
    assert ok is True
    ok, reason = server._validate_redirect_uri("https://other.example.com/cb")
    assert ok is False
    assert "allow-list" in reason


# IMAP mailbox / UID validation


def test_mailbox_valid_quoted():
    assert server._validate_mailbox("INBOX") == '"INBOX"'
    assert server._validate_mailbox("Deleted Messages") == '"Deleted Messages"'
    assert server._validate_mailbox("Sent/Archive") == '"Sent/Archive"'


@pytest.mark.parametrize(
    "bad",
    [
        '',                        # empty
        'INBOX"; SELECT "Trash',   # contains quote
        r'a\b',                    # contains backslash
        'Hello\nWorld',            # contains LF
        'Hello\rWorld',            # contains CR
        'Hello\x00World',          # contains NUL
        'Hello\x07Bell',           # contains BEL
    ],
)
def test_mailbox_invalid_rejected(bad):
    with pytest.raises(ValueError):
        server._validate_mailbox(bad)


def test_mailbox_non_string_rejected():
    with pytest.raises(ValueError):
        server._validate_mailbox(None)  # type: ignore[arg-type]


def test_uid_valid():
    assert server._validate_uid("123") == b"123"
    assert server._validate_uid("1") == b"1"


@pytest.mark.parametrize(
    "bad",
    ["1:*", "1,2,3", "1:5", "*", "abc", "", "-1", "12 34", "1\n2"],
)
def test_uid_invalid_rejected(bad):
    with pytest.raises(ValueError):
        server._validate_uid(bad)


# Header / recipient validation


def test_validate_header_value_accepts_clean():
    assert server._validate_header_value("Hello world", "subject") == "Hello world"


def test_validate_header_value_rejects_crlf():
    with pytest.raises(ValueError):
        server._validate_header_value("Hello\r\nBcc: x@y", "subject")
    with pytest.raises(ValueError):
        server._validate_header_value("a\nb", "subject")
    with pytest.raises(ValueError):
        server._validate_header_value("a\rb", "subject")


def test_validate_header_value_too_long():
    with pytest.raises(ValueError):
        server._validate_header_value("a" * 1001, "subject", max_len=1000)


def test_parse_recipient_list_basic():
    addrs = server._parse_recipient_list("a@x.com, b@y.com", "to")
    assert addrs == ["a@x.com", "b@y.com"]


def test_parse_recipient_list_with_display_name():
    addrs = server._parse_recipient_list("Alex <a@x.com>, Bob <b@y.com>", "to")
    assert addrs == ["a@x.com", "b@y.com"]


def test_parse_recipient_list_empty_string_returns_empty():
    assert server._parse_recipient_list("", "to") == []
    assert server._parse_recipient_list(None, "to") == []


def test_parse_recipient_list_rejects_crlf():
    with pytest.raises(ValueError):
        server._parse_recipient_list("a@x.com\r\nBcc: evil@z.com", "to")


def test_parse_recipient_list_rejects_malformed_address():
    with pytest.raises(ValueError):
        server._parse_recipient_list("not-an-email", "to")
    with pytest.raises(ValueError):
        server._parse_recipient_list("@nodomain.com", "to")


def test_parse_recipient_list_caps_count(monkeypatch):
    many = ", ".join(f"u{i}@x.com" for i in range(server.MAX_RECIPIENTS + 1))
    with pytest.raises(ValueError):
        server._parse_recipient_list(many, "to")


# Limit clamp


def test_clamp_limit_within_range():
    assert server._clamp_limit(50) == 50


def test_clamp_limit_clamps_high():
    assert server._clamp_limit(10_000) == server.MAX_MAIL_LIMIT


def test_clamp_limit_clamps_low():
    assert server._clamp_limit(0) == 1
    assert server._clamp_limit(-5) == 1


def test_clamp_limit_rejects_non_integer():
    with pytest.raises(ValueError):
        server._clamp_limit("abc")


# ICS escape + VEVENT serialization


def test_ics_escape_handles_separators():
    assert server._ics_escape("a, b; c") == "a\\, b\\; c"


def test_ics_escape_escapes_backslash():
    # Backslash must be doubled before any other replacement.
    assert server._ics_escape("a\\b") == "a\\\\b"


def test_ics_escape_normalises_line_endings():
    assert server._ics_escape("line1\nline2") == "line1\\nline2"
    assert server._ics_escape("line1\rline2") == "line1\\nline2"
    assert server._ics_escape("line1\r\nline2") == "line1\\nline2"


def test_ics_escape_strips_c0_controls():
    # NUL, BEL, FF, vertical tab are all stripped; TAB and newline survive.
    raw = "x\x00y\x07z\x0bq\x0cw\x7fz"
    assert server._ics_escape(raw) == "xyzqwz"
    assert server._ics_escape("a\tb") == "a\tb"


def test_build_vevent_ics_uses_crlf_line_endings():
    start = dt.datetime(2026, 1, 1, 9, 0, 0)
    end = dt.datetime(2026, 1, 1, 10, 0, 0)
    ics = server._build_vevent_ics(
        uid="abc@example",
        summary="meeting",
        start=start,
        end=end,
        tzid="America/New_York",
        description=None,
        location=None,
        rrule=None,
        include_location=False,
    )
    assert ics.endswith("\r\n")
    # Every line break is CRLF; never a bare LF.
    assert "\n" not in ics.replace("\r\n", "")
    assert "BEGIN:VCALENDAR\r\n" in ics
    assert "BEGIN:VEVENT\r\n" in ics


# RRULE


def test_build_rrule_returns_none_for_none():
    assert server._build_rrule(None, tzid="UTC") is None


def test_build_rrule_returns_none_for_empty_dict():
    # Empty-dict shortcut: documented to mean "no recurrence".
    assert server._build_rrule({}, tzid="UTC") is None


def test_build_rrule_rejects_non_dict():
    with pytest.raises(ValueError):
        server._build_rrule("daily", tzid="UTC")  # type: ignore[arg-type]


def test_build_rrule_requires_frequency():
    with pytest.raises(ValueError):
        server._build_rrule({"interval": 2}, tzid="UTC")


def test_build_rrule_unknown_frequency():
    with pytest.raises(ValueError):
        server._build_rrule({"frequency": "fortnightly"}, tzid="UTC")


def test_build_rrule_invalid_interval():
    with pytest.raises(ValueError):
        server._build_rrule({"frequency": "daily", "interval": 0}, tzid="UTC")
    with pytest.raises(ValueError):
        server._build_rrule({"frequency": "daily", "interval": -3}, tzid="UTC")


def test_build_rrule_invalid_weekday():
    with pytest.raises(ValueError):
        server._build_rrule(
            {"frequency": "weekly", "by_weekday": ["MO", "ZZ"]}, tzid="UTC"
        )


def test_build_rrule_invalid_monthday():
    with pytest.raises(ValueError):
        server._build_rrule(
            {"frequency": "monthly", "by_monthday": [0]}, tzid="UTC"
        )
    with pytest.raises(ValueError):
        server._build_rrule(
            {"frequency": "monthly", "by_monthday": [32]}, tzid="UTC"
        )


def test_build_rrule_end_on_date():
    rule = server._build_rrule(
        {"frequency": "daily", "end": {"type": "on_date", "date": "2026-12-31"}},
        tzid="UTC",
    )
    assert rule is not None
    assert "FREQ=DAILY" in rule
    assert "UNTIL=" in rule


def test_build_rrule_end_after_occurrences():
    rule = server._build_rrule(
        {"frequency": "weekly", "end": {"type": "after_occurrences", "count": 5}},
        tzid="UTC",
    )
    assert rule is not None
    assert "COUNT=5" in rule


def test_build_rrule_end_invalid_count():
    with pytest.raises(ValueError):
        server._build_rrule(
            {"frequency": "weekly", "end": {"type": "after_occurrences", "count": 0}},
            tzid="UTC",
        )


def test_build_rrule_end_unknown_type():
    with pytest.raises(ValueError):
        server._build_rrule(
            {"frequency": "daily", "end": {"type": "forever"}}, tzid="UTC"
        )
