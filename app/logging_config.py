"""Structured logging setup.

`structlog` renders to a human-readable console format locally and to JSON in
deployed environments, so log aggregation works without a parsing layer. The
standard library `logging` module is routed through the same pipeline so that
uvicorn/sqlalchemy/apscheduler output lands in the same format.
"""

from __future__ import annotations

import logging
import sys

import structlog

_configured = False


def configure_logging(level: str = "INFO", fmt: str = "console") -> None:
    global _configured
    if _configured:
        return

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
        structlog.processors.StackInfoRenderer(),
    ]

    renderer: structlog.typing.Processor
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
        pre_render = [structlog.processors.format_exc_info]
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
        pre_render = [structlog.processors.format_exc_info]

    structlog.configure(
        processors=[
            *shared_processors,
            *pre_render,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn installs its own handlers; drop them so records propagate to root.
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True

    # Uvicorn's access log is silenced outright, and this is a security control
    # rather than a formatting preference.
    #
    # It logs the full request target *including the query string*, so a
    # password-reset visit writes `GET /reset-password?token=<the actual token>`
    # into the log stream in plaintext — handing anyone with log access a live
    # account-takeover credential. The app emits its own structured request line
    # (`app.main`) carrying method, path, status and duration but never the
    # query, which is strictly more useful and does not leak.
    #
    # Silenced here rather than via uvicorn's `access_log=False` because that
    # flag only takes effect through uvicorn's own dictConfig, which is skipped
    # when `log_config=None`. Doing it on the logger works no matter how the
    # server was launched, including a bare `uvicorn app.main:app`.
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True

    # These are chatty at INFO and say nothing useful in normal operation.
    logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
