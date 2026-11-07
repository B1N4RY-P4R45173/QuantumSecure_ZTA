# SDP Controller — Policy Decision Point.
#
# Build context is the project root (ztna-sdp/), never this folder — the
# Controller imports the shared/ package:
#   docker build -f ./docker/controller/Dockerfile -t sdp-controller .
#
# This is the decision that used to run inside the Gateway process. Pulling it
# out means the component that enforces no longer also decides: the Gateway
# asks over mutual TLS and does what the answer says. The policy file, the
# telemetry snapshot and the trust scorer now live behind a network boundary
# the Gateway cannot cross except by asking a question.
#
# SDP_GATEWAY/ is deliberately NOT copied in. The decision has no business
# reaching into the enforcer, and the Controller never dials out at all — it
# only answers a Gateway that connected to it.
#
# Runs as a non-root user, unlike the Gateway. The Gateway needs CAP_NET_ADMIN
# for nftables and CAP_NET_BIND_SERVICE for port 443; this service binds a high
# port and touches no firewall, so it needs no capability whatsoever.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/SDP_CONTROLLER

WORKDIR /app

# Dependencies first, for layer caching.
COPY SDP_CONTROLLER/requirements.txt ./SDP_CONTROLLER/requirements.txt
RUN pip install --no-cache-dir -r SDP_CONTROLLER/requirements.txt

# Application code: the Controller, and the shared library it needs for the
# project CA's TLS contexts, the knock-ticket posture bits and the logger.
COPY shared/ ./shared/
COPY SDP_CONTROLLER/ ./SDP_CONTROLLER/

WORKDIR /app/SDP_CONTROLLER
# Strip host dev state that slipped into the build context. certs/pki is
# mounted read-only at runtime from the bundle `admin_cli.py
# issue-controller-cert` writes, so it must be empty here — an image is copied
# around and must never carry a private key.
RUN rm -rf certs .venv __pycache__ */__pycache__ */*/__pycache__ \
    && mkdir -p certs/pki \
    && useradd --system --uid 10004 --home /app controller \
    && chown -R controller:controller /app
USER controller

EXPOSE 9500

# /healthz sits behind the same mutual TLS as /spa_verify, so the probe has to
# present a client certificate — an anonymous one cannot finish the handshake,
# let alone reach a route.
#
# It presents health.crt, the small client certificate issue-controller-cert
# mints for exactly this. controller.crt will NOT do: a TLS server refuses a
# server certificate offered as a client certificate ("sslv3 alert unsupported
# certificate"), because the extended-key-usage field says which kind it is.
# Borrowing a Gateway's certificate would work, but it would put a Gateway's
# private key on the Controller host, which is the one thing splitting these
# two processes was meant to avoid.
#
# Dialled as "localhost" because that name is in the certificate's SAN list and
# the probe verifies the host name like any other client would.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import http.client,ssl,sys; ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.minimum_version=ssl.TLSVersion.TLSv1_3; ctx.load_verify_locations('certs/pki/ca.crt'); ctx.load_cert_chain('certs/pki/health.crt','certs/pki/health.key'); c=http.client.HTTPSConnection('localhost',9500,context=ctx,timeout=3); c.request('GET','/healthz'); sys.exit(0 if c.getresponse().status==200 else 1)"]

CMD ["python", "main.py"]
