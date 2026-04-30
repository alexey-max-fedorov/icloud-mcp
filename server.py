# server.py
# iCloud MCP connector — Calendar (CalDAV), Mail (IMAP/SMTP), and OAuth.

from __future__ import annotations

import os
import logging
import datetime as dt
import secrets
import hashlib
import base64
import time
import contextlib
import html as html_lib
import imaplib
import smtplib
import re
import ssl
import email as _email_mod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header, decode_header as _decode_rfc2047
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Iterator, Optional, Any
from zoneinfo import ZoneInfo

import icalendar
from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, HTMLResponse, RedirectResponse

from caldav.davclient import DAVClient
from caldav.lib import error as dav_error

# Configuration / Env

# Load .env that lives next to this file, regardless of CWD.
load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=False)


def _require_env(name: str, default: Optional[str] = None) -> str:
    """Return a required environment variable, or raise if missing."""
    value = os.environ.get(name, default)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value.strip()

APPLE_ID: str    = _require_env("APPLE_ID")
APP_PW: str      = _require_env("ICLOUD_APP_PASSWORD")
CALDAV_URL: str  = _require_env("CALDAV_URL", "https://caldav.icloud.com")
DEFAULT_TZID: str = os.environ.get("TZID", "America/New_York").strip()

LOOKBACK_YEARS = 3  # for UID searches
SERVER_HOST = os.environ.get("HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("PORT", "8000"))

# Add DR profile + scan window
DR_ONLY = os.environ.get("DR_PROFILE", "0") == "1"
SCAN_DAYS = int(os.environ.get("SCAN_DAYS", str(LOOKBACK_YEARS * 365)))

# Mail (IMAP / SMTP) — set MAIL_ENABLED=1 to activate mail tools
MAIL_ENABLED    = os.environ.get("MAIL_ENABLED", "0") == "1"
IMAP_HOST       = os.environ.get("IMAP_HOST", "imap.mail.me.com").strip()
IMAP_PORT       = int(os.environ.get("IMAP_PORT", "993"))
SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp.mail.me.com").strip()
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "587"))
IMAP_TIMEOUT    = float(os.environ.get("IMAP_TIMEOUT", "30"))
SMTP_TIMEOUT    = float(os.environ.get("SMTP_TIMEOUT", "30"))
ICLOUD_TRASH    = os.environ.get("ICLOUD_TRASH_FOLDER", "Deleted Messages")

# OAuth config — if both vars are set, Bearer-token auth is enforced on /mcp
OAUTH_CLIENT_ID     = os.environ.get("OAUTH_CLIENT_ID", "").strip()
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "").strip()
OAUTH_ENABLED       = bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET)
def _load_redirect_uris() -> tuple[str, ...]:
    raw_list = os.environ.get("OAUTH_REDIRECT_URIS", "")
    single = os.environ.get("OAUTH_REDIRECT_URI", "").strip()
    uris = {u.strip() for u in raw_list.split(",") if u.strip()}
    if single:
        uris.add(single)
    return tuple(sorted(uris))

OAUTH_REDIRECT_URIS = _load_redirect_uris()

CODE_TTL  = 60           # auth codes expire in 60 seconds
TOKEN_TTL = 86400 * 30   # access tokens live 30 days
_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_LOCALHOST_REDIRECT_HOSTS = {"localhost", "127.0.0.1", "::1"}
_TLS_CONTEXT = ssl.create_default_context()

# Validation
# IMAP astring chars: printable ASCII, excluding the quoting char (") and escape (\).
_MAILBOX_RE = re.compile(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]+$')
_UID_RE = re.compile(r'^\d+$')
_HEADER_FORBIDDEN_RE = re.compile(r'[\r\n]')
# C0 controls except TAB(0x09), LF(0x0a), CR(0x0d) — and DEL(0x7f).
_C0_CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

MAX_MAIL_LIMIT = 200
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_SUBJECT_LEN = 998   # RFC 5322 §2.1.1
MAX_RECIPIENTS = 100
MAX_SEARCH_QUERY_LEN = 1024

# In-memory OAuth state (tokens lost on restart — user re-authorizes after deploys)
_auth_codes: dict[str, dict] = {}    # code → {client_id, redirect_uri, code_challenge, ...}
_access_tokens: dict[str, dict] = {} # token → {client_id, expires_at}

# Optional: simple logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("icloud-caldav")


# OAuth helpers

def _is_valid_pkce_verifier(verifier: str) -> bool:
    """RFC 7636 code_verifier format: unreserved chars, length 43..128."""
    return bool(_PKCE_VERIFIER_RE.fullmatch(verifier or ""))


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    """Verify an OAuth 2.0 PKCE code_verifier against a stored code_challenge."""
    if method != "S256" or not _is_valid_pkce_verifier(verifier):
        return False
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(expected, challenge)


def _validate_redirect_uri(redirect_uri: str) -> tuple[bool, str]:
    """Validate OAuth redirect URIs for safety and MCP interoperability."""
    if not redirect_uri:
        return False, "redirect_uri required"

    parsed = urlparse(redirect_uri)
    if not parsed.scheme or not parsed.netloc:
        return False, "redirect_uri must be an absolute URI"
    if parsed.fragment:
        return False, "redirect_uri must not include a fragment"
    if parsed.username or parsed.password:
        return False, "redirect_uri must not include userinfo"

    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and host in _LOCALHOST_REDIRECT_HOSTS:
        pass
    else:
        return False, "redirect_uri must be https or localhost http"

    if OAUTH_REDIRECT_URIS and redirect_uri not in OAUTH_REDIRECT_URIS:
        return False, "redirect_uri is not allow-listed"

    return True, ""


class _BearerAuthMiddleware(BaseHTTPMiddleware):
    """Require a valid Bearer token on /mcp when OAuth is enabled."""
    _SKIP = {"/.well-known/oauth-authorization-server", "/authorize", "/token", "/health"}

    async def dispatch(self, request, call_next):
        if not OAUTH_ENABLED or request.url.path in self._SKIP:
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="icloud-mcp"'},
            )
        token = auth[7:].strip()
        entry = _access_tokens.get(token)
        if not entry or entry["expires_at"] < time.time():
            _access_tokens.pop(token, None)
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer realm="icloud-mcp", error="invalid_token", '
                        'error_description="The access token expired or is invalid"'
                    )
                },
            )
        return await call_next(request)


# MCP app

mcp = FastMCP("icloud-caldav")

@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request: Request) -> JSONResponse:
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    })


@mcp.custom_route("/authorize", methods=["GET", "POST"])
async def authorize(request: Request):
    esc = html_lib.escape
    if request.method == "GET":
        params = dict(request.query_params)
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        if not OAUTH_ENABLED or client_id != OAUTH_CLIENT_ID:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        ok, reason = _validate_redirect_uri(redirect_uri)
        if not ok:
            return JSONResponse(
                {"error": "invalid_request", "error_description": reason},
                status_code=400,
            )
        hidden = "".join(
            f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">'
            for k, v in params.items()
        )
        page = f"""<!DOCTYPE html>
<html><head><title>iCloud MCP — Authorize</title>
<style>
  body {{font-family:system-ui;max-width:440px;margin:4em auto;padding:0 1.5em;color:#1d1d1f}}
  h2 {{font-size:1.4rem;margin-bottom:.5em}}
  p  {{color:#6e6e73;margin-bottom:1.5em}}
  button {{background:#0071e3;color:#fff;border:none;padding:.75em 1.75em;
           border-radius:8px;font-size:1rem;cursor:pointer}}
  button:hover {{background:#0077ed}}
</style></head><body>
<h2>Allow access to your iCloud Calendar?</h2>
<p>Client: <strong>{esc(params.get("client_id", ""))}</strong></p>
<form method="POST">{hidden}
  <button type="submit">Authorize</button>
</form></body></html>"""
        return HTMLResponse(page)

    # POST — user clicked Authorize
    form = await request.form()
    client_id             = str(form.get("client_id", ""))
    redirect_uri          = str(form.get("redirect_uri", ""))
    code_challenge        = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", "S256"))
    state                 = str(form.get("state", ""))

    if not OAUTH_ENABLED or client_id != OAUTH_CLIENT_ID:
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    ok, reason = _validate_redirect_uri(redirect_uri)
    if not ok:
        return JSONResponse(
            {"error": "invalid_request", "error_description": reason},
            status_code=400,
        )
    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge required"},
            status_code=400,
        )
    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge_method must be S256"},
            status_code=400,
        )

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + CODE_TTL,
    }
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}" + (f"&state={state}" if state else "")
    return RedirectResponse(location, status_code=302)


@mcp.custom_route("/token", methods=["POST"])
async def token_endpoint(request: Request) -> JSONResponse:
    form          = await request.form()
    grant_type    = str(form.get("grant_type", ""))
    code          = str(form.get("code", ""))
    redirect_uri  = str(form.get("redirect_uri", ""))
    code_verifier = str(form.get("code_verifier", ""))
    client_id     = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))

    # Also accept HTTP Basic Auth (some clients send credentials this way)
    basic = request.headers.get("Authorization", "")
    if basic.startswith("Basic "):
        try:
            decoded = base64.b64decode(basic[6:]).decode()
            client_id, _, client_secret = decoded.partition(":")
        except Exception:
            pass

    if not OAUTH_ENABLED:
        return JSONResponse({"error": "oauth_not_configured"}, status_code=503)
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not client_id or not client_secret:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if not secrets.compare_digest(client_id, OAUTH_CLIENT_ID) or \
       not secrets.compare_digest(client_secret, OAUTH_CLIENT_SECRET):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    entry = _auth_codes.pop(code, None)
    if not entry or entry["expires_at"] < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if entry["redirect_uri"] != redirect_uri or entry["client_id"] != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if not _is_valid_pkce_verifier(code_verifier):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "invalid code_verifier"},
            status_code=400,
        )
    if not _verify_pkce(
        code_verifier, entry["code_challenge"], entry["code_challenge_method"]
    ):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE mismatch"},
            status_code=400,
        )

    token = secrets.token_urlsafe(48)
    _access_tokens[token] = {"client_id": client_id, "expires_at": time.time() + TOKEN_TTL}
    log.info("OAuth: issued access token for client %r", client_id)
    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
    })


# CalDAV helpers


def _client() -> DAVClient:
    """Return a new stateless DAV client."""
    return DAVClient(url=CALDAV_URL, username=APPLE_ID, password=APP_PW)


def _principal():
    """Return the authenticated CalDAV principal (raises on auth failure)."""
    return _client().principal()


def _all_calendars():
    """Return all calendars for the authenticated principal."""
    return _principal().calendars()


def _resolve_calendar(name_or_url: str):
    """Return a caldav.Calendar from a display name or absolute URL."""
    for calendar in _all_calendars():
        if calendar.name == name_or_url or str(calendar.url) == name_or_url:
            return calendar
    # Fallback: instantiate by URL directly
    return _client().calendar(url=name_or_url)

def _parse_iso(s: str) -> dt.datetime:
    """
    Accept 'YYYY-MM-DDTHH:MM:SS' (naive/local) or '...Z' (UTC) or with offset.
    """
    if s.endswith("Z"):
        return dt.datetime.fromisoformat(s[:-1]).replace(tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(s)


def _scan_window() -> tuple[dt.datetime, dt.datetime]:
    """Return the time window used for DR search/fetch operations."""
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=SCAN_DAYS)
    end = now + dt.timedelta(days=SCAN_DAYS)
    return start, end


def _uid_search_window() -> tuple[dt.datetime, dt.datetime]:
    """Return the wide time window used for UID-based lookups."""
    now = dt.datetime.now(dt.timezone.utc)
    delta = dt.timedelta(days=365 * LOOKBACK_YEARS)
    return now - delta, now + delta

def _fmt(ts: dt.datetime) -> str:
    """Format as 'YYYYMMDDTHHMMSS' for ICS."""
    return ts.strftime("%Y%m%dT%H%M%S")

def _fmt_utc(ts: dt.datetime) -> str:
    """Format as 'YYYYMMDDTHHMMSSZ' in UTC for ICS."""
    # If naive, assume default TZ, then convert to UTC
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=ZoneInfo(DEFAULT_TZID))
    ts_utc = ts.astimezone(dt.timezone.utc)
    return ts_utc.strftime("%Y%m%dT%H%M%SZ")

def _ics_escape(text: str) -> str:
    """RFC 5545 escaping for TEXT-typed properties (SUMMARY/DESCRIPTION/LOCATION)."""
    text = _C0_CONTROL_RE.sub("", text)
    return (
        text.replace("\\", "\\\\")
            .replace("\r\n", "\\n")
            .replace("\r", "\\n")
            .replace("\n", "\\n")
            .replace(",", "\\,")
            .replace(";", "\\;")
    )

def _to_iso(o) -> Optional[str]:
    """Best-effort ISO formatter for date/time values."""
    if o is None:
        return None
    if isinstance(o, dt.datetime):
        return o.isoformat()
    try:
        return o.isoformat()
    except Exception:
        return str(o)


def _parse_iso_or_default(value: Optional[str], fallback: dt.datetime) -> dt.datetime:
    """Parse an ISO datetime string or return the fallback if missing."""
    if value is None:
        return fallback
    return _parse_iso(value)


def _normalize_to_tz(ts: dt.datetime, tzid: str) -> dt.datetime:
    """Return ``ts`` normalized into the given IANA timezone."""
    tz = ZoneInfo(tzid)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=tz)
    return ts.astimezone(tz)


def _build_vevent_ics(
    uid: str,
    summary: str,
    start: dt.datetime,
    end: dt.datetime,
    tzid: str,
    description: Optional[str],
    location: Optional[str],
    rrule: Optional[str],
    *,
    include_location: bool,
) -> str:
    """Build a minimal VEVENT ICS blob."""
    lines: List[str] = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//ChatGPT MCP iCloud CalDAV//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"SUMMARY:{_ics_escape(summary)}",
        f"DTSTART;TZID={tzid}:{_fmt(start)}",
        f"DTEND;TZID={tzid}:{_fmt(end)}",
    ]

    if include_location and location is not None and location != "":
        lines.append(f"LOCATION:{_ics_escape(location)}")
    if description:
        lines.append(f"DESCRIPTION:{_ics_escape(description)}")
    if rrule:
        lines.append(f"RRULE:{rrule}")

    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"

def _build_rrule(
    recurrence: Optional[Dict[str, Any]],
    tzid: str,
    dtstart: Optional[dt.datetime] = None,
) -> Optional[str]:
    """Build an RFC5545 RRULE value from a high-level recurrence dict."""
    if recurrence is None:
        return None
    if not isinstance(recurrence, dict):
        raise ValueError("recurrence must be an object")
    if not recurrence:
        return None

    freq = (recurrence.get("frequency") or "").lower()
    if not freq:
        raise ValueError("recurrence.frequency is required")

    if freq == "custom":
        raw = recurrence.get("rrule")
        if not raw:
            raise ValueError("recurrence.rrule is required when frequency='custom'")
        value = str(raw).strip()
        if not value:
            raise ValueError("recurrence.rrule must be non-empty")
        return value

    freq_map = {
        "daily": "DAILY",
        "weekly": "WEEKLY",
        "monthly": "MONTHLY",
        "yearly": "YEARLY",
    }
    if freq not in freq_map:
        raise ValueError("Unsupported recurrence.frequency")

    parts: List[str] = [f"FREQ={freq_map[freq]}"]

    interval = recurrence.get("interval")
    if interval is not None:
        if not isinstance(interval, int) or interval < 1:
            raise ValueError("recurrence.interval must be an integer >= 1")
        if interval > 1:
            parts.append(f"INTERVAL={interval}")

    by_weekday = recurrence.get("by_weekday") or []
    if by_weekday:
        valid_days = {"MO", "TU", "WE", "TH", "FR", "SA", "SU"}
        days = [str(d).upper() for d in by_weekday]
        if any(day not in valid_days for day in days):
            raise ValueError("recurrence.by_weekday contains invalid values")
        parts.append(f"BYDAY={','.join(days)}")
    elif freq == "weekly" and dtstart is not None:
        weekday_map = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
        parts.append(f"BYDAY={weekday_map[dtstart.weekday()]}")

    by_monthday = recurrence.get("by_monthday") or []
    if by_monthday:
        days_int: List[int] = []
        for day in by_monthday:
            day_int = int(day)
            if day_int == 0 or day_int < -31 or day_int > 31:
                raise ValueError("recurrence.by_monthday values must be in [-31..-1] or [1..31]")
            days_int.append(day_int)
        days = [str(day) for day in days_int]
        parts.append(f"BYMONTHDAY={','.join(days)}")

    end = recurrence.get("end") or {}
    if not isinstance(end, dict):
        raise ValueError("recurrence.end must be an object")
    end_type = (end.get("type") or "").lower()
    if end_type == "on_date":
        date_str = end.get("date")
        if not date_str:
            raise ValueError("recurrence.end.date is required when end.type='on_date'")
        if len(date_str) == 10:
            y, m, d = map(int, date_str.split("-"))
            local_dt = dt.datetime(y, m, d, 23, 59, 59)
        else:
            local_dt = dt.datetime.fromisoformat(date_str)
        if local_dt.tzinfo is None:
            local_dt = local_dt.replace(tzinfo=ZoneInfo(tzid))
        until_utc = local_dt.astimezone(dt.timezone.utc)
        until_str = until_utc.strftime("%Y%m%dT%H%M%SZ")
        parts.append(f"UNTIL={until_str}")
    elif end_type == "after_occurrences":
        count = end.get("count")
        if not isinstance(count, int) or count <= 0:
            raise ValueError("recurrence.end.count must be an integer > 0")
        parts.append(f"COUNT={count}")
    elif end_type:
        raise ValueError("Unsupported recurrence.end.type")

    return ";".join(parts) if parts else None

# ── Mail helpers ──────────────────────────────────────────────────────────────

def _imap() -> imaplib.IMAP4_SSL:
    """Return a new authenticated IMAP connection (stateless — one per call)."""
    conn = imaplib.IMAP4_SSL(
        IMAP_HOST,
        IMAP_PORT,
        ssl_context=_TLS_CONTEXT,
        timeout=IMAP_TIMEOUT,
    )
    conn.login(APPLE_ID, APP_PW)
    return conn


def _validate_mailbox(name: str) -> str:
    """Validate an IMAP mailbox name and return its quoted-astring form."""
    if not isinstance(name, str) or not name:
        raise ValueError("mailbox name required")
    if not _MAILBOX_RE.fullmatch(name):
        raise ValueError("mailbox name contains invalid characters")
    return f'"{name}"'


def _validate_uid(uid: str) -> bytes:
    """Validate an IMAP UID is a single positive integer; return its bytes form.

    Refuses sequence sets like '1:*' or '1,2,3' to prevent bulk operations
    against a mailbox via a single tool call.
    """
    if not isinstance(uid, str) or not _UID_RE.fullmatch(uid):
        raise ValueError("uid must be a positive integer")
    return uid.encode("ascii")


def _clamp_limit(limit: Any) -> int:
    """Clamp a user-supplied result limit into [1, MAX_MAIL_LIMIT]."""
    try:
        n = int(limit)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    return max(1, min(n, MAX_MAIL_LIMIT))


def _validate_header_value(value: Optional[str], field_name: str, max_len: int = 998) -> str:
    """Reject header values containing CR/LF (header injection)."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if _HEADER_FORBIDDEN_RE.search(value):
        raise ValueError(f"{field_name} must not contain CR or LF")
    if len(value) > max_len:
        raise ValueError(f"{field_name} exceeds {max_len} characters")
    return value


def _parse_recipient_list(value: Optional[str], field_name: str) -> List[str]:
    """Parse a comma-separated recipient string and return validated addresses.

    Rejects CR/LF anywhere in the input and any address that doesn't look
    like a valid mailbox per RFC 5322 (basic shape).
    """
    if not value:
        return []
    if _HEADER_FORBIDDEN_RE.search(value):
        raise ValueError(f"{field_name} must not contain CR or LF")
    addrs: List[str] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name, addr = parseaddr(raw)
        if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
            raise ValueError(f"invalid email address in {field_name}: {raw!r}")
        if _HEADER_FORBIDDEN_RE.search(addr) or _HEADER_FORBIDDEN_RE.search(name):
            raise ValueError(f"invalid characters in {field_name}")
        addrs.append(addr)
    if len(addrs) > MAX_RECIPIENTS:
        raise ValueError(f"{field_name} exceeds {MAX_RECIPIENTS} recipients")
    return addrs


@contextlib.contextmanager
def _imap_session(
    mailbox: Optional[str] = None,
    *,
    readonly: bool = False,
) -> Iterator[imaplib.IMAP4_SSL]:
    """Open an IMAP session, optionally SELECT a validated mailbox, and clean up."""
    conn = _imap()
    try:
        if mailbox is not None:
            conn.select(_validate_mailbox(mailbox), readonly=readonly)
        yield conn
    finally:
        try:
            conn.logout()
        except Exception as exc:
            log.debug("IMAP logout failed: %s", exc)


def _decode_header(value: str) -> str:
    """Decode an RFC 2047-encoded mail header value to plain Unicode."""
    parts = _decode_rfc2047(value or "")
    out = []
    for raw, charset in parts:
        if isinstance(raw, bytes):
            out.append(raw.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(str(raw))
    return "".join(out)


def _extract_body(msg: _email_mod.message.Message) -> str:
    """Extract the best plain-text body from an email.Message."""
    if msg.is_multipart():
        plain = None
        html = None
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            if ct == "text/plain" and plain is None:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    plain = payload.decode(charset, errors="replace")
            elif ct == "text/html" and html is None:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    html = payload.decode(charset, errors="replace")
        if plain is not None:
            return plain
        if html is not None:
            return re.sub(r"<[^>]+>", "", html)
        return ""
    else:
        charset = msg.get_content_charset() or "utf-8"
        payload = msg.get_payload(decode=True)
        return payload.decode(charset, errors="replace") if payload else ""


def _uid_from_meta(meta: bytes) -> str:
    """Extract UID integer from an IMAP FETCH response metadata line."""
    m = re.search(rb"\bUID\s+(\d+)\b", meta, re.IGNORECASE)
    return m.group(1).decode() if m else "?"


def _flags_from_meta(meta: bytes) -> List[str]:
    """Extract flag names (e.g. 'Seen', 'Flagged') from FETCH metadata."""
    m = re.search(rb"FLAGS\s+\(([^)]*)\)", meta, re.IGNORECASE)
    if not m:
        return []
    return [f.decode().lstrip("\\") for f in m.group(1).split()]


# ── Mail MCP tools ─────────────────────────────────────────────────────────────

if MAIL_ENABLED:

    @mcp.tool()
    def list_mailboxes() -> List[Dict[str, Any]]:
        """List all iCloud Mail mailboxes (folders)."""
        with _imap_session() as conn:
            status, data = conn.list()
            if status != "OK":
                return []
            out = []
            for item in data:
                if not item:
                    continue
                line = item.decode() if isinstance(item, bytes) else str(item)
                # Format: (\Flags) "delimiter" "Name"  or  (\Flags) "delimiter" Name
                m = re.search(r'"([^"]+)"\s*$', line)
                if not m:
                    m = re.search(r'\s(\S+)\s*$', line)
                name = m.group(1) if m else line.strip()
                out.append({"name": name})
            return out

    @mcp.tool()
    def list_messages(
        mailbox: str = "INBOX",
        limit: int = 20,
        unread_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List recent messages in a mailbox with headers.
        Returns [{uid, subject, from, date, read}] newest-first.
        ``limit`` is clamped to MAX_MAIL_LIMIT.
        """
        limit = _clamp_limit(limit)
        with _imap_session(mailbox, readonly=True) as conn:
            criteria = "UNSEEN" if unread_only else "ALL"
            status, data = conn.uid("SEARCH", None, criteria)
            if status != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()
            uids = uids[-limit:][::-1]  # newest first, capped at limit
            if not uids:
                return []
            uid_list = b",".join(uids)
            status, fetch_data = conn.uid(
                "FETCH", uid_list,
                "(FLAGS BODY[HEADER.FIELDS (FROM SUBJECT DATE)])"
            )
            if status != "OK":
                return []
            out = []
            for item in fetch_data:
                if not isinstance(item, tuple) or len(item) != 2:
                    continue
                meta, header_bytes = item
                if not isinstance(meta, bytes):
                    meta = str(meta).encode()
                uid_val = _uid_from_meta(meta)
                flags = _flags_from_meta(meta)
                msg = _email_mod.message_from_bytes(header_bytes)
                out.append({
                    "uid": uid_val,
                    "subject": _decode_header(msg.get("Subject", "")),
                    "from": _decode_header(msg.get("From", "")),
                    "date": msg.get("Date", ""),
                    "read": "Seen" in flags,
                })
            return out

    @mcp.tool()
    def get_message(uid: str, mailbox: str = "INBOX") -> Dict[str, Any]:
        """
        Fetch a full message by UID.
        Returns {uid, subject, from, to, cc, date, body, read}.
        Refuses messages larger than MAX_MESSAGE_BYTES.
        """
        uid_bytes = _validate_uid(uid)
        with _imap_session(mailbox, readonly=True) as conn:
            size_status, size_data = conn.uid("FETCH", uid_bytes, "(RFC822.SIZE)")
            if size_status != "OK" or not size_data or size_data[0] is None:
                return {"error": f"Message UID {uid} not found in {mailbox}"}
            size_match = re.search(rb"RFC822\.SIZE\s+(\d+)", size_data[0] if isinstance(size_data[0], bytes) else b"")
            if size_match and int(size_match.group(1)) > MAX_MESSAGE_BYTES:
                return {
                    "error": (
                        f"Message UID {uid} is {int(size_match.group(1))} bytes, "
                        f"larger than MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES})"
                    )
                }
            status, data = conn.uid("FETCH", uid_bytes, "(FLAGS RFC822)")
            if status != "OK" or not data or data[0] is None:
                return {"error": f"Message UID {uid} not found in {mailbox}"}
            for item in data:
                if not isinstance(item, tuple) or len(item) != 2:
                    continue
                meta, raw = item
                if not isinstance(meta, bytes):
                    meta = str(meta).encode()
                flags = _flags_from_meta(meta)
                msg = _email_mod.message_from_bytes(raw)
                return {
                    "uid": uid,
                    "subject": _decode_header(msg.get("Subject", "")),
                    "from": _decode_header(msg.get("From", "")),
                    "to": _decode_header(msg.get("To", "")),
                    "cc": _decode_header(msg.get("Cc", "")),
                    "date": msg.get("Date", ""),
                    "body": _extract_body(msg),
                    "read": "Seen" in flags,
                }
            return {"error": f"Message UID {uid} not found"}

    @mcp.tool()
    def search_messages(
        query: str,
        mailbox: str = "INBOX",
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Search messages by text (subject + body).
        Returns [{uid, subject, from, date}] newest-first.
        ``limit`` is clamped to MAX_MAIL_LIMIT.
        """
        if not isinstance(query, str) or not query:
            raise ValueError("query is required")
        if len(query) > MAX_SEARCH_QUERY_LEN:
            raise ValueError(f"query exceeds {MAX_SEARCH_QUERY_LEN} characters")
        if _HEADER_FORBIDDEN_RE.search(query):
            raise ValueError("query must not contain CR or LF")
        limit = _clamp_limit(limit)
        with _imap_session(mailbox, readonly=True) as conn:
            # Pass the query as bytes so imaplib uses an IMAP literal
            # (length-prefixed) instead of a quoted astring — safe regardless
            # of content.
            status, data = conn.uid(
                "SEARCH", "CHARSET", "UTF-8", "TEXT", query.encode("utf-8")
            )
            if status != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()[-limit:][::-1]
            if not uids:
                return []
            uid_list = b",".join(uids)
            status, fetch_data = conn.uid(
                "FETCH", uid_list,
                "(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])"
            )
            if status != "OK":
                return []
            out = []
            for item in fetch_data:
                if not isinstance(item, tuple) or len(item) != 2:
                    continue
                meta, header_bytes = item
                if not isinstance(meta, bytes):
                    meta = str(meta).encode()
                uid_val = _uid_from_meta(meta)
                msg = _email_mod.message_from_bytes(header_bytes)
                out.append({
                    "uid": uid_val,
                    "subject": _decode_header(msg.get("Subject", "")),
                    "from": _decode_header(msg.get("From", "")),
                    "date": msg.get("Date", ""),
                })
            return out

    @mcp.tool()
    def send_message(
        to: str,
        subject: str,
        body: str,
        cc: Optional[str] = None,
        bcc: Optional[str] = None,
    ) -> bool:
        """
        Send an email via iCloud SMTP. `to`, `cc`, `bcc` may be comma-separated.
        Returns True on success. Rejects header injection in subject/recipients.
        """
        # Header-injection hardening: validate every input that lands in a
        # MIME header or in the SMTP envelope.
        subject = _validate_header_value(subject, "subject", max_len=MAX_SUBJECT_LEN)
        to_addrs = _parse_recipient_list(to, "to")
        cc_addrs = _parse_recipient_list(cc, "cc")
        bcc_addrs = _parse_recipient_list(bcc, "bcc")
        if not to_addrs:
            raise ValueError("to is required")
        if not isinstance(body, str):
            raise ValueError("body must be a string")
        recipients = to_addrs + cc_addrs + bcc_addrs
        if len(recipients) > MAX_RECIPIENTS:
            raise ValueError(f"total recipients exceed {MAX_RECIPIENTS}")

        msg = MIMEMultipart()
        msg["From"] = APPLE_ID
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = Header(subject, "utf-8")
        if cc_addrs:
            msg["Cc"] = ", ".join(cc_addrs)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as conn:
                conn.ehlo()
                conn.starttls(context=_TLS_CONTEXT)
                conn.ehlo()
                conn.login(APPLE_ID, APP_PW)
                conn.sendmail(APPLE_ID, recipients, msg.as_bytes())
            log.info("SMTP: sent message to %d recipient(s)", len(recipients))
            return True
        except Exception as exc:
            log.error("SMTP send failed: %s", exc)
            return False

    @mcp.tool()
    def delete_message(uid: str, mailbox: str = "INBOX") -> bool:
        """
        Move a message to Trash by UID. Returns True on success.
        The trash folder name can be overridden via ICLOUD_TRASH_FOLDER env var
        (default: "Deleted Messages"). Only single positive-integer UIDs are
        accepted — sequence sets like '1:*' are rejected.
        """
        uid_bytes = _validate_uid(uid)
        trash_quoted = _validate_mailbox(ICLOUD_TRASH)
        try:
            with _imap_session(mailbox) as conn:
                copy_status, _ = conn.uid("COPY", uid_bytes, trash_quoted)
                if copy_status != "OK":
                    log.error("delete_message failed: could not copy UID %s to %s", uid, ICLOUD_TRASH)
                    return False
                store_status, _ = conn.uid("STORE", uid_bytes, "+FLAGS", "\\Deleted")
                if store_status != "OK":
                    log.error("delete_message failed: could not mark UID %s as deleted", uid)
                    return False
                expunge_status, _ = conn.expunge()
                if expunge_status != "OK":
                    log.error("delete_message failed: expunge failed for UID %s", uid)
                    return False
                return True
        except Exception as exc:
            log.error("delete_message failed: %s", exc)
            return False

    @mcp.tool()
    def mark_message(uid: str, mailbox: str = "INBOX", read: bool = True) -> bool:
        """Mark a message as read (read=True) or unread (read=False).

        Returns True only when the IMAP server confirmed a STORE response for
        the UID. Refuses sequence-set inputs.
        """
        uid_bytes = _validate_uid(uid)
        try:
            with _imap_session(mailbox) as conn:
                flag_op = "+FLAGS" if read else "-FLAGS"
                status, data = conn.uid("STORE", uid_bytes, flag_op, "\\Seen")
                if status != "OK":
                    return False
                # IMAP returns [None] when no message matched the UID.
                if not data or all(item is None for item in data):
                    return False
                return any(uid_bytes in item for item in data if isinstance(item, bytes))
        except Exception as exc:
            log.error("mark_message failed: %s", exc)
            return False


# DR profile: read-only search/fetch
if DR_ONLY:

    @mcp.tool(name="search")
    def search(query: str) -> List[Dict[str, Any]]:
        """
        Read-only search across SUMMARY and DESCRIPTION within a time window.
        Returns [{ id, title, snippet }]
        """
        q = (query or "").strip().lower()
        if not q:
            return []

        start, end = _scan_window()

        rows: List[Dict[str, Any]] = []
        for cal in _all_calendars():
            calname = getattr(cal, "name", None) or str(cal.url)
            for ev in cal.search(event=True, start=start, end=end, expand=True):
                comp = ev.component
                summary = str(comp.get("summary", "") or "")
                descr = str(comp.get("description", "") or "")
                haystack = (summary + "\n" + descr).lower()
                if q in haystack:
                    uid = str(comp.get("uid", "") or "").strip()
                    dtstart = comp.decoded("dtstart")
                    when = _to_iso(dtstart) or ""
                    rows.append({
                        "id": f"{str(cal.url)}|{uid}",
                        "title": summary[:200],
                        "snippet": f"{when} — {calname}",
                    })
        return rows[:200]

    @mcp.tool(name="fetch")
    def fetch(ids: List[str]) -> List[Dict[str, Any]]:
        """
        Fetch raw ICS for ids returned by search().
        Returns [{ id, mimeType: 'text/calendar', content }]
        """
        ids = ids or []
        calendars = {str(calendar.url): calendar for calendar in _all_calendars()}
        start, end = _scan_window()

        out: List[Dict[str, Any]] = []
        for ident in ids:
            try:
                cal_url, uid = ident.split("|", 1)
            except ValueError:
                continue
            cal = calendars.get(cal_url)
            if not cal:
                continue
            found_raw = None
            for ev in cal.search(event=True, start=start, end=end, expand=False):
                comp = ev.component
                if str(comp.get("uid", "") or "").strip() == uid:
                    found_raw = ev.data
                    break
            if found_raw:
                out.append({
                    "id": ident,
                    "mimeType": "text/calendar",
                    "content": found_raw,
                })
        return out

# Write-capable tools (default mode)
if not DR_ONLY:

    @mcp.tool()
    def list_calendars() -> List[Dict[str, Any]]:
        """Return available calendar containers with their name and URL."""
        calendars = _all_calendars()
        out: List[Dict[str, Any]] = []
        for calendar in calendars:
            out.append(
                {
                    "name": getattr(calendar, "name", None),
                    "url": str(calendar.url),
                    "id": getattr(calendar, "id", None),
                }
            )
        return out

    @mcp.tool()
    def list_calendars_with_events(
        start: str,
        end: str,
        expand_recurring: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Return calendars that have at least one event between ISO datetimes [start, end).
        """
        s = _parse_iso(start)
        e = _parse_iso(end)

        calendars = _all_calendars()
        out: List[Dict[str, Any]] = []

        for calendar in calendars:
            try:
                has_event = False
                for _ in calendar.search(event=True, start=s, end=e, expand=expand_recurring):
                    has_event = True
                    break
                if has_event:
                    out.append(
                        {
                            "name": getattr(calendar, "name", None),
                            "url": str(calendar.url),
                            "id": getattr(calendar, "id", None),
                        }
                    )
            except dav_error.DAVError as exc:
                log.warning("CalDAV search failed for calendar %s: %s", getattr(calendar, "name", calendar), exc)
            except Exception:
                log.exception("Unexpected error while scanning calendar %r for events", getattr(calendar, "name", calendar))

        return out

    @mcp.tool()
    def list_events(
        calendar_name_or_url: str,
        start: str,
        end: str,
        expand_recurring: bool = True,
    ) -> List[Dict[str, Any]]:
        """List events between ISO datetimes [start, end)."""
        s = _parse_iso(start)
        e = _parse_iso(end)
        cal = _resolve_calendar(calendar_name_or_url)

        events = cal.search(event=True, start=s, end=e, expand=expand_recurring)
        out: List[Dict[str, Any]] = []
        for ev in events:
            comp = ev.component
            summary = str(comp.get("summary", "")) if comp.get("summary") is not None else ""
            dtstart = comp.decoded("dtstart")
            dtend   = comp.decoded("dtend", default=None)
            uid     = str(comp.get("uid", "")) if comp.get("uid") is not None else ""

            out.append({
                "uid": uid,
                "summary": summary,
                "start": dtstart.isoformat() if hasattr(dtstart, "isoformat") else str(dtstart),
                "end":   dtend.isoformat() if (dtend and hasattr(dtend, "isoformat")) else (str(dtend) if dtend else None),
                "raw": ev.data,
            })
        return out

    @mcp.tool()
    def create_event(
        calendar_name_or_url: str,
        summary: str,
        start: str,
        end: str,
        tzid: Optional[str] = None,
        description: Optional[str] = None,
        location: Optional[str] = None,
        recurrence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create an event in the given calendar."""
        tzid = tzid or DEFAULT_TZID

        s = _normalize_to_tz(_parse_iso(start), tzid)
        e = _normalize_to_tz(_parse_iso(end), tzid)
        if e <= s:
            raise ValueError("end must be after start")

        cal = _resolve_calendar(calendar_name_or_url)

        uid = os.urandom(16).hex() + "@chatgpt-mcp"
        rrule = _build_rrule(recurrence, tzid=tzid, dtstart=s)

        ics_text = _build_vevent_ics(
            uid=uid,
            summary=summary,
            start=s,
            end=e,
            tzid=tzid,
            description=description,
            location=location,
            rrule=rrule,
            include_location=bool(location),
        )

        cal.save_event(ics_text)
        return uid

    @mcp.tool()
    def update_event(
        calendar_name_or_url: str,
        uid: str,
        summary: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        tzid: Optional[str] = None,
        description: Optional[str] = None,
        location: Optional[str] = None,
        recurrence: Optional[Dict[str, Any]] = None,
        clear_recurrence: bool = False,
    ) -> bool:
        """Update a VEVENT identified by UID."""
        cal = _resolve_calendar(calendar_name_or_url)

        s_window, e_window = _uid_search_window()

        target = None
        for ev in cal.search(event=True, start=s_window, end=e_window, expand=False):
            comp = ev.component
            if str(comp.get("uid", "")) == uid:
                target = ev
                break
        if target is None:
            return False

        cal_obj = icalendar.Calendar.from_ical(target.data)
        matching_events = [
            component
            for component in cal_obj.walk("VEVENT")
            if str(component.get("uid", "") or "").strip() == uid
        ]
        if not matching_events:
            return False

        # Prefer the master VEVENT when recurrence exceptions are present.
        comp = next(
            (component for component in matching_events if component.get("RECURRENCE-ID") is None),
            matching_events[0],
        )

        old_summary = str(comp.get("summary", "")) if comp.get("summary") is not None else ""
        old_desc = str(comp.get("description", "")) if comp.get("description") is not None else ""
        old_loc = str(comp.get("location", "")) if comp.get("location") is not None else ""
        old_dtstart = comp.decoded("dtstart")
        old_dtend = comp.decoded("dtend", default=None)

        dtstart_prop = comp.get("dtstart")
        existing_tzid = None
        if dtstart_prop is not None and hasattr(dtstart_prop, "params"):
            existing_tzid = dtstart_prop.params.get("TZID")
            if existing_tzid is not None:
                existing_tzid = str(existing_tzid)
        effective_tzid = tzid or existing_tzid or DEFAULT_TZID

        new_summary = summary if summary is not None else old_summary
        new_desc = description if description is not None else old_desc
        new_loc = location if location is not None else old_loc
        new_start = _parse_iso_or_default(start, old_dtstart)
        new_end_fallback = old_dtend if old_dtend is not None else (new_start + dt.timedelta(hours=1))
        new_end = _parse_iso_or_default(end, new_end_fallback)

        new_start = _normalize_to_tz(new_start, effective_tzid)
        new_end = _normalize_to_tz(new_end, effective_tzid)
        if new_end <= new_start:
            raise ValueError("end must be after start")

        # Strip tzinfo so icalendar serializes as floating local datetime, then
        # attach TZID via params — otherwise icalendar may emit a UTC value (Z)
        # AND a TZID parameter, which is invalid per RFC 5545 §3.3.5.
        local_start = new_start.astimezone(ZoneInfo(effective_tzid)).replace(tzinfo=None)
        local_end = new_end.astimezone(ZoneInfo(effective_tzid)).replace(tzinfo=None)

        comp["SUMMARY"] = icalendar.vText(new_summary)
        comp.pop("DTSTART", None)
        comp.pop("DTEND", None)
        comp.add("DTSTART", local_start, parameters={"TZID": effective_tzid})
        comp.add("DTEND", local_end, parameters={"TZID": effective_tzid})

        if new_desc != "":
            comp["DESCRIPTION"] = icalendar.vText(new_desc)
        else:
            comp.pop("DESCRIPTION", None)

        if new_loc != "":
            comp["LOCATION"] = icalendar.vText(new_loc)
        else:
            comp.pop("LOCATION", None)

        if clear_recurrence:
            comp.pop("RRULE", None)
        elif recurrence is not None:
            effective_rrule = _build_rrule(recurrence, tzid=effective_tzid, dtstart=new_start)
            if effective_rrule:
                comp["RRULE"] = icalendar.vRecur.from_ical(effective_rrule)
            else:
                comp.pop("RRULE", None)

        target.data = cal_obj.to_ical().decode()
        target.save()
        return True

    @mcp.tool()
    def delete_event(calendar_name_or_url: str, uid: str) -> bool:
        """Delete a VEVENT by UID from the given calendar."""
        cal = _resolve_calendar(calendar_name_or_url)

        start, end = _uid_search_window()

        for ev in cal.search(event=True, start=start, end=end, expand=False):
            comp = ev.component
            if str(comp.get("uid", "")) == uid:
                ev.delete()
                return True
        return False

# Main

if __name__ == "__main__":
    import uvicorn

    log.info(
        "Starting MCP HTTP server on %s:%s  OAuth=%s",
        SERVER_HOST, SERVER_PORT, OAUTH_ENABLED,
    )
    log.info(
        "CalDAV: %s  Apple ID: %r  TZ: %s  DR_ONLY=%s  MAIL=%s",
        CALDAV_URL, APPLE_ID, DEFAULT_TZID, DR_ONLY, MAIL_ENABLED,
    )
    if MAIL_ENABLED:
        log.info("Mail: IMAP=%s:%s  SMTP=%s:%s", IMAP_HOST, IMAP_PORT, SMTP_HOST, SMTP_PORT)

    # Obtain the Starlette ASGI app from FastMCP so we can attach middleware
    app = mcp.http_app(path="/mcp")

    if OAUTH_ENABLED:
        app.add_middleware(_BearerAuthMiddleware)
        log.info("OAuth enabled — /mcp requires Bearer token (client_id=%r)", OAUTH_CLIENT_ID)
        if OAUTH_REDIRECT_URIS:
            log.info("OAuth redirect allow-list configured (%d URI(s))", len(OAUTH_REDIRECT_URIS))
        else:
            log.warning("OAuth redirect allow-list is empty. Set OAUTH_REDIRECT_URIS for stricter redirect control.")
    else:
        log.warning("OAuth is DISABLED — /mcp is publicly accessible. Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET to enable auth.")

    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT)
