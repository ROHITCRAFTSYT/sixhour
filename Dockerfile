# Build stage: install exactly what uv.lock pins into /app/.venv. uv itself stays in this stage.
FROM python:3.15-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.11.23@sha256:d0a0a753ab981624b49c97abc98821c1c09f4ca69d1ef5cee69c501be3d88479 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app

# Dependencies first, so a code-only change reuses this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

# --locked fails the build if uv.lock no longer matches pyproject.toml.
COPY README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable


# Runtime stage: the base image plus the ready virtualenv. No uv, no build tools.
FROM python:3.15-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/app/.venv/bin:$PATH HOST=0.0.0.0 PORT=8080
WORKDIR /app
RUN useradd --system --no-create-home app
COPY --from=build /app/.venv /app/.venv

USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['PORT'], timeout=2)" || exit 1
CMD ["sixhour"]
