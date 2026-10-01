"""Activity log. Records event names and file names only, never secrets."""
import os
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(os.environ.get("SFV_LOG_PATH", "data/activity.log"))


def log_event(event: str, detail: str = "") -> None:
    line = f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC | {event} | {detail[:200]}"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line.replace("\n", " ") + "\n")
    except OSError:
        pass  # logging must never break the app


def read_log(limit: int = 200) -> list[str]:
    try:
        return LOG_PATH.read_text(encoding="utf-8").splitlines()[-limit:][::-1]
    except OSError:
        return []
