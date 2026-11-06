"""Low-level packet-filter primitives for opening a single hole through the
Gateway: (src_ip -> [dst_ip] : dst_port/protocol).

Two backends, picked once at import time:

  * nftables (`nft`)    — preferred where available
  * iptables            — fallback, and what the container image ships today

Both require root or CAP_NET_ADMIN — the Gateway container should run with
`cap_add: [NET_ADMIN]`, not full --privileged. When neither backend is usable
(missing binary, insufficient permission — e.g. running this outside its
container during development) every call degrades to a logged dry-run instead
of raising, so the rest of the SPA flow can still be exercised and tested.

`mode()` names which of the three is in force, so startup can say so plainly
rather than leaving an operator to infer it from the absence of errors.

The optional `dst_ip` argument is what makes `acl = LIMITED` enforceable: a
grant can be pinned to one destination host instead of every resource behind
the Gateway. Omitted, the hole reaches any destination, which is `acl = FULL`.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from shared.utils.logger import get_logger, status

log = get_logger("Firewall")

_IPTABLES = shutil.which("iptables")
_NFT = shutil.which("nft")

CHAIN = "SDP_SPA"          # iptables chain name
NFT_TABLE = "sdp_spa"      # nftables table name
NFT_CHAIN = "input"

MODE_NFTABLES = "nftables"
MODE_IPTABLES = "iptables"
MODE_DRY_RUN = "dry-run"

# Set once: a backend does not appear or disappear while the Gateway runs.
_FORCE_DRY_RUN = os.environ.get("GATEWAY_FORCE_DRY_RUN") == "1"
_HAS_PRIV = os.geteuid() == 0
_PREFER_NFT = os.environ.get("GATEWAY_FIREWALL_BACKEND", "").lower() != "iptables"

if _FORCE_DRY_RUN or not _HAS_PRIV:
    _MODE = MODE_DRY_RUN
elif _NFT is not None and _PREFER_NFT:
    _MODE = MODE_NFTABLES
elif _IPTABLES is not None:
    _MODE = MODE_IPTABLES
else:
    _MODE = MODE_DRY_RUN


def mode() -> str:
    """Which backend is in force: nftables, iptables or dry-run."""
    return _MODE


def _usable() -> bool:
    return _MODE != MODE_DRY_RUN


def _why_dry_run() -> str:
    if _FORCE_DRY_RUN:
        return "GATEWAY_FORCE_DRY_RUN=1"
    if not _HAS_PRIV:
        return "not running as root / without CAP_NET_ADMIN"
    return "neither nft nor iptables found"


def _run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


# --------------------------------------------------------------------------- #
# Chain setup                                                                 #
# --------------------------------------------------------------------------- #

def ensure_chain(chain: str = CHAIN) -> None:
    """Idempotently create the Gateway's chain, hook it into the input path and
    default it to DROP.

    ACCEPT rules inserted by allow() go in front of the trailing DROP — this is
    the actual mechanism behind "ports stay closed until a valid SPA knock
    precedes any connection attempt".
    """
    if not _usable():
        status(log, "[DRY-RUN] would ensure chain", chain=chain, reason=_why_dry_run())
        return

    if _MODE == MODE_NFTABLES:
        _ensure_chain_nft()
        return

    create = _run([_IPTABLES, "-N", chain])
    if create.returncode != 0 and "already exists" not in create.stderr:
        status(log, "Firewall chain creation failed", chain=chain, error=create.stderr.strip())
        return

    linked = _run([_IPTABLES, "-C", "INPUT", "-j", chain])
    if linked.returncode != 0:
        _run([_IPTABLES, "-A", "INPUT", "-j", chain], check=True)
        _run([_IPTABLES, "-A", chain, "-j", "DROP"], check=True)
    status(log, "Firewall chain ready", chain=chain, backend=_MODE)


def _ensure_chain_nft() -> None:
    _run([_NFT, "add", "table", "inet", NFT_TABLE])
    _run([_NFT, "add", "chain", "inet", NFT_TABLE, NFT_CHAIN,
          "{ type filter hook input priority 0 ; policy accept ; }"])
    _run([_NFT, "flush", "chain", "inet", NFT_TABLE, NFT_CHAIN])
    # Established flows survive the posture coming up, so bringing the Gateway
    # online does not cut a connection that is already through.
    _run([_NFT, "add", "rule", "inet", NFT_TABLE, NFT_CHAIN,
          "ct", "state", "established,related", "accept"])
    status(log, "Firewall chain ready", table=NFT_TABLE, chain=NFT_CHAIN, backend=_MODE)


def protect_ports(ports: list[int], protocol: str = "tcp") -> None:
    """Install the default-DROP rule for each protected service port.

    Only meaningful on nftables, where the Gateway owns its own chain with an
    accept policy; the iptables chain already ends in a blanket DROP.
    """
    if not _usable():
        status(log, "[DRY-RUN] would protect ports", ports=ports, reason=_why_dry_run())
        return
    if _MODE != MODE_NFTABLES:
        return
    for port in ports:
        _run([_NFT, "add", "rule", "inet", NFT_TABLE, NFT_CHAIN,
              protocol, "dport", str(port), "drop"])
    status(log, "Default-DROP installed", ports=ports, backend=_MODE)


# --------------------------------------------------------------------------- #
# Per-session holes                                                           #
# --------------------------------------------------------------------------- #

def allow(src_ip: str, dst_port: int, protocol: str = "tcp",
          dst_ip: str | None = None) -> bool:
    """Open one hole. `dst_ip` pins it to a single destination host."""
    if not _usable():
        status(log, "[DRY-RUN] would ALLOW", src_ip=src_ip, dst_ip=dst_ip or "any",
               port=dst_port, protocol=protocol, reason=_why_dry_run())
        return False

    if _MODE == MODE_NFTABLES:
        cmd = [_NFT, "insert", "rule", "inet", NFT_TABLE, NFT_CHAIN,
               "ip", "saddr", src_ip]
        if dst_ip:
            cmd += ["ip", "daddr", dst_ip]
        cmd += [protocol, "dport", str(dst_port), "accept"]
    else:
        cmd = [_IPTABLES, "-I", CHAIN, "1", "-s", src_ip]
        if dst_ip:
            cmd += ["-d", dst_ip]
        cmd += ["-p", protocol, "--dport", str(dst_port), "-j", "ACCEPT"]

    result = _run(cmd)
    if result.returncode != 0:
        status(log, "Firewall insert failed", error=result.stderr.strip())
        return False
    status(log, "Firewall rule inserted", src_ip=src_ip, dst_ip=dst_ip or "any",
           port=dst_port, protocol=protocol, backend=_MODE)
    return True


def revoke(src_ip: str, dst_port: int, protocol: str = "tcp",
           dst_ip: str | None = None) -> None:
    """Close a hole previously opened with the same arguments."""
    if not _usable():
        status(log, "[DRY-RUN] would REVOKE", src_ip=src_ip, dst_ip=dst_ip or "any",
               port=dst_port, protocol=protocol, reason=_why_dry_run())
        return

    if _MODE == MODE_NFTABLES:
        # nftables deletes by handle, so the matching rule has to be found
        # first; iptables can delete by specification directly.
        handle = _find_nft_handle(src_ip, dst_port, protocol, dst_ip)
        if handle is None:
            status(log, "Firewall revoke skipped - rule not found",
                   src_ip=src_ip, port=dst_port)
            return
        cmd = [_NFT, "delete", "rule", "inet", NFT_TABLE, NFT_CHAIN, "handle", str(handle)]
    else:
        cmd = [_IPTABLES, "-D", CHAIN, "-s", src_ip]
        if dst_ip:
            cmd += ["-d", dst_ip]
        cmd += ["-p", protocol, "--dport", str(dst_port), "-j", "ACCEPT"]

    result = _run(cmd)
    if result.returncode != 0:
        status(log, "Firewall revoke failed", error=result.stderr.strip())
        return
    status(log, "Firewall rule revoked", src_ip=src_ip, dst_ip=dst_ip or "any", port=dst_port)


def _find_nft_handle(src_ip: str, dst_port: int, protocol: str,
                     dst_ip: str | None) -> int | None:
    listing = _run([_NFT, "-a", "list", "chain", "inet", NFT_TABLE, NFT_CHAIN])
    if listing.returncode != 0:
        return None
    for line in listing.stdout.splitlines():
        if f"saddr {src_ip}" not in line or f"dport {dst_port}" not in line:
            continue
        if dst_ip and f"daddr {dst_ip}" not in line:
            continue
        if protocol not in line or "handle" not in line:
            continue
        try:
            return int(line.rsplit("handle", 1)[1].strip())
        except (IndexError, ValueError):
            continue
    return None


def teardown() -> None:
    """Remove everything this Gateway installed. Called on shutdown."""
    if not _usable():
        status(log, "[DRY-RUN] would tear down the chain", reason=_why_dry_run())
        return
    if _MODE == MODE_NFTABLES:
        _run([_NFT, "delete", "table", "inet", NFT_TABLE])
    else:
        _run([_IPTABLES, "-D", "INPUT", "-j", CHAIN])
        _run([_IPTABLES, "-F", CHAIN])
        _run([_IPTABLES, "-X", CHAIN])
    status(log, "Firewall chain torn down", backend=_MODE)
