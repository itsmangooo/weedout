"""Server entrypoint: ``python -m app``.

Why this exists rather than just documenting ``uvicorn app.main:app``:

When uvicorn is given an import string it creates its event loop *first* and
imports the application *second*. Anything the app module does at import time —
including switching Windows off the ProactorEventLoop that psycopg cannot use —
therefore happens too late, and the first database query fails at runtime.

Running through this module sets the policy before uvicorn starts, so local
development on Windows behaves the same as the Linux container. On Linux it is
an ordinary uvicorn launch with settings-driven configuration.
"""

from __future__ import annotations

import os

import uvicorn

from app.config import get_settings
from app.db import configure_event_loop_policy, run_async


def main() -> None:
    configure_event_loop_policy()

    settings = get_settings()
    reload = settings.environment == "local" and settings.debug

    config = uvicorn.Config(
        "app.main:app",
        host=os.environ.get("HOST", "0.0.0.0"),  # noqa: S104 - containers bind all interfaces
        port=int(os.environ.get("PORT", "8000")),
        reload=reload,
        reload_dirs=["app"] if reload else None,
        # Logging is configured by the app itself through structlog; uvicorn's
        # own dictConfig would install a second, differently-formatted handler.
        log_config=None,
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )

    if reload:
        # Reload needs uvicorn's supervisor process, which owns loop setup.
        # It installs a selector loop for its worker on Windows, so this path
        # is already compatible with psycopg.
        uvicorn.run(config.app, **_reload_kwargs(config))
        return

    # Non-reload: run the server on a loop we choose. uvicorn would otherwise
    # install the proactor policy here, which psycopg cannot use.
    run_async(uvicorn.Server(config).serve())


def _reload_kwargs(config: uvicorn.Config) -> dict:
    return {
        "host": config.host,
        "port": config.port,
        "reload": True,
        "reload_dirs": config.reload_dirs,
        "log_config": None,
        "access_log": False,
        "proxy_headers": True,
        "forwarded_allow_ips": config.forwarded_allow_ips,
    }


if __name__ == "__main__":
    main()
