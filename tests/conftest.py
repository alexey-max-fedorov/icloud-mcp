"""Set required env vars and import path so ``server`` loads under pytest."""

import os
import sys
from pathlib import Path

os.environ.setdefault("APPLE_ID", "test@example.com")
os.environ.setdefault("ICLOUD_APP_PASSWORD", "abcd-efgh-ijkl-mnop")
os.environ.setdefault("CALDAV_URL", "https://caldav.icloud.com")
os.environ.setdefault("TZID", "America/New_York")
os.environ.setdefault("MAIL_ENABLED", "0")

# Project root is the parent of tests/ — add it so `import server` works.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
