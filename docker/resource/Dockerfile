# Protected resource node.
#
# Build context is the project root (ztna-sdp/), never this folder — the node
# imports the shared/ package:
#   docker build -f ./docker/resource/Dockerfile -t resource-node .
#
# Sits on data-plane-net alone, so it is reachable only through the Gateway
# and has no route to the IDP. It therefore cannot fetch the JWKS: it
# validates access tokens offline against the IDP's RS256 public key, mounted
# read-only at runtime. Without that key it exits 1 rather than serving
# anything unverified.
#
# Serves plain HTTP. The inner leg is deliberately cleartext because the
# Gateway has already terminated the client's TLS and this network is
# internal-only.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/resource-node

WORKDIR /app

# Dependencies first, for layer caching.
COPY resource-node/requirements.txt ./resource-node/requirements.txt
RUN pip install --no-cache-dir -r resource-node/requirements.txt

COPY shared/ ./shared/
COPY resource-node/ ./resource-node/

WORKDIR /app/resource-node
RUN rm -rf certs .venv __pycache__ */__pycache__ */*/__pycache__ \
    && mkdir -p certs \
    && useradd --system --uid 10003 --home /app resource \
    && chown -R resource:resource /app
USER resource

EXPOSE 7443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7443/healthz').status==200 else 1)"]

CMD ["python", "main.py"]
