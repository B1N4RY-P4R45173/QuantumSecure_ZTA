#!/usr/bin/env python3
"""ztna - the client, one stage per command, for a live demonstration.

main.py runs all six stages in one process, which is right for an agent and
wrong for a demo: a reviewer sees a wall of log and cannot tell which command
caused what. This drives the SAME modules, one stage at a time, so each beat
of the flow is a command you type and a result you point at.

    ztna login      first factor, TPM, FIDO2 -> tokens + the Gateway's key
    ztna knock      one ML-KEM-sealed UDP packet -> SPA_OK
    ztna connect    TLS through the pinhole to the resource
    ztna status     what this session is holding right now
    ztna whoami     decode the access token and show its claims
    ztna logout     forget it

Nothing is reimplemented here. login() calls fido2_agent.client, knock()
calls spa.token_flow, connect() calls dataplane.session - the same code paths
main.py uses. If this worked and main.py did not, the demo would be a lie.

State lives in demo/.session.json between commands, because each command is
its own process. It holds the tokens and the Gateway's public key; the FIDO2
private key is NOT in it and never leaves the TPM.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / "SDP_CLIENT"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(CLIENT))
os.chdir(CLIENT)          # the CA path and credential cache are relative to it

import requests                                              # noqa: E402

from dataplane import session as dataplane                   # noqa: E402
from fido2_agent import client as fido2                      # noqa: E402
from fido2_agent import credential_cache                     # noqa: E402
from posture import checker                                  # noqa: E402
from spa import token_flow                                   # noqa: E402
from tpm.anchored_trust import (TrustAnchorUnavailable,       # noqa: E402
                                select_trust_anchor)
from wireguard import keys as wg_keys                        # noqa: E402
from shared.config.settings import settings                  # noqa: E402

STATE = Path(__file__).resolve().parent / ".session.json"

B, D, G, R, Y, N = ("\033[1m", "\033[2m", "\033[32m", "\033[31m",
                    "\033[33m", "\033[0m")


def head(text: str) -> None:
    print(f"\n{B}{text}{N}")


def note(text: str) -> None:
    print(f"{D}  {text}{N}")


def ok(text: str) -> None:
    print(f"{G}  {text}{N}")


def bad(text: str) -> None:
    print(f"{R}  {text}{N}")


def field(label: str, value) -> None:
    print(f"  {label:<26} {value}")


# --------------------------------------------------------------------------- #
# session state                                                               #
# --------------------------------------------------------------------------- #

def load() -> dict:
    if not STATE.exists():
        bad("No session. Run:  ztna login")
        raise SystemExit(1)
    return json.loads(STATE.read_text(encoding="utf-8"))


def save(data: dict) -> None:
    STATE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    STATE.chmod(0o600)          # it holds bearer tokens


def claims(token: str) -> dict:
    """Decode a JWT payload. No verification - this is for display only, and
    the Gateway and the resource both verify it properly."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# ztna login                                                                  #
# --------------------------------------------------------------------------- #

def cmd_login(args) -> int:
    username = args.username or os.environ.get("CLIENT_USERNAME")
    password = args.password or os.environ.get("CLIENT_PASSWORD")
    if not username or not password:
        bad("Need --username and --password (or CLIENT_USERNAME/CLIENT_PASSWORD)")
        return 2

    head(f"[1/3] First factor -> {settings.idp_base_url}")
    note("Password alone proves nothing here. It buys a short-lived")
    note("login_token that only authorises the FIDO2 ceremony below.")
    device_id = (settings.client_device_id
                 or str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                   f"{username}@{uuid.getnode():x}")))
    try:
        login_data = fido2.login(username, password, device_id)
    except requests.HTTPError as exc:
        bad(f"IDP rejected the first factor: "
            f"{exc.response.text[:200] if exc.response is not None else exc}")
        return 1
    except requests.RequestException as exc:
        bad(f"IDP unreachable: {exc}")
        return 1

    login_token = login_data["login_token"]
    enrolled = bool(login_data.get("device_enrolled"))
    ok(f"accepted  device_id={device_id[:18]}...  enrolled={enrolled}")

    head("[2/3] Hardware trust anchor")
    note("No software fallback. If no anchor can be found, the client aborts")
    note("rather than identifying itself with a key that could be copied.")
    try:
        anchor = select_trust_anchor(username)
    except TrustAnchorUnavailable as exc:
        bad(f"no hardware trust anchor: {exc}")
        return 1
    ok(f"{anchor.kind}  backend={anchor.backend}  simulated={anchor.simulated}")

    posture = None
    try:
        posture = checker.collect(device_id, anchor.kind, trust_anchor_present=True)
        field("os_patch_days", posture.os_patch_days)
        field("disk_encrypted", posture.disk_encrypted)
        field("antivirus_active", posture.antivirus_active)
        note("")
        note("This is a REPORT, not a verdict. The client never scores itself:")
        note("the IDP decides which bits the report earns, adds the three it")
        note("attests itself, and signs all six into the knock ticket.")
    except Exception as exc:
        note(f"posture snapshot failed, bits pack as false: {exc}")

    head("[3/3] FIDO2 ceremony")
    cached = credential_cache.load(username, anchor.backend)
    registering = cached is None or not enrolled
    note("register: the TPM makes a key and CERTIFIES it; the IDP checks that"
         if registering else
         "authenticate: the TPM signs a challenge with the key it already holds")
    note("certificate before it will enrol the credential."
         if registering else "and the IDP verifies the signature.")

    origin = f"https://{settings.rp_id}"
    try:
        if registering:
            credential_id = fido2.register(login_token, anchor, settings.rp_id, origin)
            credential_cache.save(username, anchor.backend, credential_id)
        else:
            credential_id = cached
        _priv, wg_public = wg_keys.load_or_generate()
        bundle = fido2.authenticate(login_token, credential_id, anchor,
                                    settings.rp_id, origin, wg_public,
                                    posture=posture)
    except requests.HTTPError as exc:
        bad(f"ceremony rejected: "
            f"{exc.response.text[:200] if exc.response is not None else exc}")
        return 1

    if bundle.get("status") != "granted":
        bad(f"IDP did not grant a token: {bundle.get('status')}")
        return 1

    try:
        gateway_key = token_flow.gateway_key_from_bundle(bundle)
        ticket = token_flow.ticket_from_bundle(bundle)
    except (token_flow.GatewayKeyMissing, token_flow.KnockTicketMissing) as exc:
        bad(f"bundle is missing what the knock needs: {exc}")
        return 1

    save({
        "username": username,
        "device_id": device_id,
        "credential_id": base64.b64encode(credential_id).decode(),
        "access_token": bundle["access_token"],
        "refresh_token": bundle["refresh_token"],
        "gateway_key": base64.b64encode(gateway_key).decode(),
        "ticket": base64.b64encode(ticket).decode(),
        "ticket_used": False,
        "expires_in": bundle.get("expires_in"),
        "hardware_attested": bundle.get("hardware_attested"),
        "issued_at": time.time(),
    })

    c = claims(bundle["access_token"])
    print()
    ok("SESSION ESTABLISHED")
    field("hardware attested", bundle.get("hardware_attested"))
    field("auth methods (amr)", c.get("amr"))
    field("roles", c.get("roles"))
    field("audience", c.get("aud"))
    field("access token ttl", f"{bundle.get('expires_in')}s")
    field("knock ticket", f"{len(ticket)} bytes, single use")
    field("gateway ML-KEM key", f"{len(gateway_key)} bytes")
    note("")
    note("No pinhole exists yet. The Gateway's port is still dark.")
    note("Next:  ztna knock")
    return 0


# --------------------------------------------------------------------------- #
# ztna knock                                                                  #
# --------------------------------------------------------------------------- #

def cmd_knock(args) -> int:
    state = load()
    gateway_key = base64.b64decode(state["gateway_key"])

    head(f"SPA knock -> {settings.gateway_ip}:{settings.gateway_spa_port_client}/udp")

    # A ticket is single use at the Gateway, so a second knock needs a new
    # one. Reusing it would be rejected as a replay, which is the point.
    if state.get("ticket_used"):
        note("the previous ticket is spent - asking the IDP for a fresh one")
        try:
            ticket = fido2.knock_ticket(state["refresh_token"])
        except requests.RequestException as exc:
            bad(f"could not get a knock ticket: {exc}")
            return 1
        state["ticket"] = base64.b64encode(ticket).decode()
    else:
        ticket = base64.b64decode(state["ticket"])

    note(f"ticket: {len(ticket)} bytes, ES256-signed by the IDP, carrying the")
    note("attested posture bits the Gateway will read only after checking")
    note("that signature")
    note("sealing it: ML-KEM-768 encapsulation -> HKDF-SHA256 -> AES-256-GCM")
    print()

    accepted = token_flow.request_access(
        gateway_key, ticket,
        settings.client_access_port, settings.client_access_protocol)

    state["ticket_used"] = True
    save(state)
    print()

    if accepted:
        ok("SPA_OK - the Gateway opened a leased pinhole for this source IP")
        note("Look at the Gateway pane: knock received, forwarded to the")
        note("Controller, decision returned, firewall rule inserted.")
        note("Next:  ztna connect")
        return 0

    bad("No reply.")
    note("That is not a bug and not a timeout to debug on the spot: an")
    note("unaccepted knock is DROPPED, never refused. An attacker learns")
    note("nothing from being turned away - not even that anything is here.")
    note("Why it was refused is in the Controller pane, not on the wire.")
    return 1


# --------------------------------------------------------------------------- #
# ztna connect                                                                #
# --------------------------------------------------------------------------- #

def cmd_connect(args) -> int:
    state = load()
    head(f"Data path -> {settings.gateway_ip}:{settings.client_access_port} "
         f"({dataplane.RESOURCE_PATH})")
    note(f"verifying the Gateway against the project CA: {dataplane.ca_cert_path()}")
    note("SPA_OK only proved a pinhole exists. This proves access.")
    print()

    try:
        result = dataplane.fetch(state["access_token"], settings.gateway_ip,
                                 settings.client_access_port)
    except dataplane.CaCertMissing as exc:
        bad(f"no project CA to verify the Gateway with: {exc}")
        return 1
    except dataplane.DataPlaneError as exc:
        bad(f"request failed: {exc}")
        note("If the knock was accepted, the usual causes are a lease that")
        note("has since expired or a session revoked by re-evaluation.")
        return 1

    print()
    if result.ok:
        ok(f"HTTP {result.status_code} in {result.elapsed_ms:.1f} ms")
    else:
        bad(f"HTTP {result.status_code}")
    field("body", result.body[:200])
    note("")
    note("The Gateway terminated this TLS and opened a separate connection")
    note("to the resource - it is an inspection point, not a tunnel. And the")
    note("resource verified the token itself; it does not trust the Gateway.")
    return 0 if result.ok else 1


# --------------------------------------------------------------------------- #
# ztna status / whoami / logout                                               #
# --------------------------------------------------------------------------- #

def cmd_status(args) -> int:
    if not STATE.exists():
        head("No session")
        note("Run:  ztna login")
        return 0
    state = json.loads(STATE.read_text(encoding="utf-8"))
    age = time.time() - state.get("issued_at", 0)
    ttl = state.get("expires_in") or 0

    head("Session held by this client")
    field("username", state["username"])
    field("hardware attested", state.get("hardware_attested"))
    field("access token age", f"{age:.0f}s of {ttl}s")
    field("knock ticket", "spent" if state.get("ticket_used") else "unused")
    note("")
    note("This is what the CLIENT holds. Whether a pinhole is open is the")
    note("Gateway's state, not the client's:")
    note("  docker exec sdp-gateway nft list table inet sdp_spa")
    return 0


def cmd_whoami(args) -> int:
    state = load()
    c = claims(state["access_token"])
    head("Access token claims (decoded, not verified - the resource verifies)")
    for key in ("sub", "aud", "iss", "roles", "amr", "exp", "iat"):
        if key in c:
            value = c[key]
            if key in ("exp", "iat"):
                value = f"{value}  ({time.strftime('%H:%M:%S', time.localtime(value))})"
            field(key, value)
    note("")
    note("amr lists how this subject authenticated: pwd, fido2, hwattest.")
    note("The resource node checks this signature offline against the IDP's")
    note("public key - it has no route to the IDP to ask.")
    return 0


def cmd_logout(args) -> int:
    if STATE.exists():
        STATE.unlink()
        head("Session forgotten")
        note("The enrolled FIDO2 credential survives - it is in the TPM, not here.")
    else:
        head("No session to forget")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="ztna", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("login", help="first factor, TPM, FIDO2 -> tokens")
    p.add_argument("--username")
    p.add_argument("--password")
    p.set_defaults(func=cmd_login)

    sub.add_parser("knock", help="one ML-KEM-sealed packet -> SPA_OK").set_defaults(func=cmd_knock)
    sub.add_parser("connect", help="TLS through the pinhole to the resource").set_defaults(func=cmd_connect)
    sub.add_parser("status", help="what this session holds").set_defaults(func=cmd_status)
    sub.add_parser("whoami", help="decode the access token").set_defaults(func=cmd_whoami)
    sub.add_parser("logout", help="forget the session").set_defaults(func=cmd_logout)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
