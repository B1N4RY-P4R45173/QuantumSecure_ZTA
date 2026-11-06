# SDP Client — device agent.
#
# Build context is the project root (ztna-sdp/), never this folder — the
# client imports the shared/ package:
#   docker build -f ./docker/client/Dockerfile -t sdp-client .
#
# WORKDIR is SDP_CLIENT so `from dataplane import session` resolves and the
# relative default CLIENT_CA_CERT_PATH=./certs/pki/ca.crt lands where the
# compose mount puts the project CA. That CA is the client's only trust
# anchor for the Gateway's proxy certificate; without it the agent refuses
# the data path rather than connecting unverified.
#
# Note: the FIDO2 ceremony needs a hardware trust anchor (TPM or an external
# security key). Neither is available to a container by default, so this
# image is for the SPA and data-path legs; run the agent natively for a full
# enrolment.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/SDP_CLIENT

WORKDIR /app

# Dependencies first, for layer caching.
COPY SDP_CLIENT/requirements.txt ./SDP_CLIENT/requirements.txt
RUN pip install --no-cache-dir -r SDP_CLIENT/requirements.txt

COPY shared/ ./shared/
COPY SDP_CLIENT/ ./SDP_CLIENT/

WORKDIR /app/SDP_CLIENT
# certs/pki is mounted read-only at runtime with the project CA, so it must
# be empty in the image — a stale CA baked into a layer would be trusted.
RUN rm -rf certs .venv __pycache__ */__pycache__ */*/__pycache__ \
    && mkdir -p certs/pki certs/credentials \
    && useradd --system --uid 10002 --home /app client \
    && chown -R client:client /app
USER client

CMD ["python", "main.py"]
