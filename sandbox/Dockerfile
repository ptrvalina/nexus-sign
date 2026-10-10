# NEXUS-SIGN sandbox: container image.
# Standard library only: no packages are installed.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8787

WORKDIR /app
COPY server ./server
COPY web ./web
COPY config ./config

RUN useradd --system --no-create-home --shell /usr/sbin/nologin sandbox
USER sandbox

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/v1/health', timeout=2)"

CMD ["python", "server/main.py"]
