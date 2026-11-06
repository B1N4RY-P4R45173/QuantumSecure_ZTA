# SDP Gateway — Policy Enforcement Point.
#
# Build context is the project root (ztna-sdp/), never this folder — the
# Gateway imports both shared/ and SDP_CONTROLLER/:
#   docker build -f ./docker/gateway/Dockerfile -t sdp-gateway .
#
# The Gateway is the only component on all three networks. It terminates the
# client's TLS on the proxy port, inspects the decrypted request, and
# re-forwards it to the resource over the internal cleartext leg.
#
# SDP_CONTROLLER/ is copied in because controller/policy_controller.py
# imports the trust scorer and policy engine from it. Without it the Gateway
# falls back to nothing — it fails closed at startup.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/SDP_GATEWAY

WORKDIR /app

# nftables for the packet-filter backend. The Gateway prefers nft and falls
# back to iptables; both are present so either backend works, and it degrades
# to a logged dry-run if the container is started without CAP_NET_ADMIN.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iptables \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, for layer caching.
COPY SDP_GATEWAY/requirements.txt ./SDP_GATEWAY/requirements.txt
RUN pip install --no-cache-dir -r SDP_GATEWAY/requirements.txt

# Application code: the Gateway, the shared library, and the Controller's
# trust scorer + policy engine that PolicyController evaluates against.
COPY shared/ ./shared/
COPY SDP_CONTROLLER/ ./SDP_CONTROLLER/
COPY SDP_GATEWAY/ ./SDP_GATEWAY/

WORKDIR /app/SDP_GATEWAY
# Strip host dev state that slipped into the build context. certs/pki is
# mounted read-only at runtime from the CA bundle, so it must be empty here.
RUN rm -rf certs .venv __pycache__ */__pycache__ */*/__pycache__ \
    && mkdir -p certs/pki

# Runs as root deliberately: the Gateway inserts nftables rules (CAP_NET_ADMIN)
# and binds the privileged proxy port 443 (CAP_NET_BIND_SERVICE). Both
# capabilities are granted in docker-compose.yml rather than --privileged.
# Dropping to an unprivileged user would silently demote the firewall to
# dry-run, which looks like it is working while enforcing nothing.

EXPOSE 443/tcp 62201/udp

CMD ["python", "main.py"]
