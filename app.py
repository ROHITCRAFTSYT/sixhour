"""Vercel entrypoint: Vercel's FastAPI support serves the `app` exported here."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sixhour.server import app  # noqa: E402

__all__ = ["app"]
