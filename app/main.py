"""ASGI entrypoint for the SENTINEL v0.1 API."""

from app.api.app import create_app


app = create_app()
