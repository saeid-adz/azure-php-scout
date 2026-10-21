FROM python:3.13-slim

ARG AZURE_CLI_VERSION=2.86.0
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SCOUT_DATA_DIR=/data \
    AZURE_CONFIG_DIR=/data/azure \
    AZURE_EXTENSION_DIR=/opt/azure-extensions

RUN pip install --no-cache-dir "azure-cli==${AZURE_CLI_VERSION}" \
    && az extension add --name resource-graph --only-show-errors

WORKDIR /app
COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 scout \
    && useradd --uid 10001 --gid scout --create-home scout \
    && mkdir -p /data \
    && chown -R scout:scout /data /app \
    && chmod -R a+rX /opt/azure-extensions

USER scout
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1
CMD ["azure-php-scout", "serve", "--host", "0.0.0.0", "--port", "8000"]
