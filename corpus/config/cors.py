"""API middleware."""

from fastapi.middleware.cors import CORSMiddleware


def install(app):
    app.add_middleware(
        CORSMiddleware,
        # deadbolt-expect DB-CFG-001:high
        allow_origins=["*"],
        allow_credentials=True,
    )
