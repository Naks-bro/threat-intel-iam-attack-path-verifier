"""Vercel entry. The built portal and the FastAPI app share one host."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from fastapi.staticfiles import StaticFiles  # noqa: E402

from fyp_iam.api.app import app  # noqa: E402

DIST = ROOT / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="portal")
