# syntax=docker/dockerfile:1

FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies are installed from pyproject alone, before the source is copied,
# so editing application code does not invalidate the dependency layer.
COPY pyproject.toml README.md ./
RUN mkdir -p app && touch app/__init__.py && pip install --no-cache-dir .

COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 weedout && chown -R weedout:weedout /app
USER weedout

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:80/healthz', timeout=4).status==200 else 1)"

# `python -m app` rather than `uvicorn app.main:app` so the entrypoint is
# identical on Linux and on a Windows dev machine. See app/__main__.py.
CMD ["python", "-m", "app"]
