"""Explicit offline ASGI entry point. No environment database URL is loaded."""

from fyp_iam.api.app import create_app

app = create_app(database_url=None, foundry_preview=True)
