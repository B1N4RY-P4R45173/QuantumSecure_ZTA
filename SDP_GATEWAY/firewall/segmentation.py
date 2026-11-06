"""Grants a client temporary access after a valid SPA knock, scoped by the
Controller's ACL decision, and closes it again when the lease runs out.

Micro-segmentation is expressed as the set of destination hosts a grant may
reach:

  FULL     every resource behind the Gateway
  LIMITED  only the hosts the Controller named
  DENY     never reaches here; the listener drops the knock first

That is the whole of what an ACL can mean at layers 3 and 4, which is the
layer this module works at: a destination set, not a set of permitted
operations.

A read-only or per-endpoint restriction would have to be enforced by
proxy/ and traffic/, which do read the decrypted request and could express
it. It is not implemented there either, so no ACL in this system currently
restricts what a client may DO with a destination it is allowed to reach —
only which destinations those are.

The lease itself is held by firewall.sessions.TABLE, whose reaper closes it;
this module only translates a decision into a grant.
"""

from __future__ import annotations

import uuid

from firewall.sessions import TABLE
from shared.utils.logger import get_logger, status

log = get_logger("Segmentation")

DEFAULT_TTL_SECONDS = 30

ACL_FULL = "FULL"
ACL_LIMITED = "LIMITED"
ACL_DENY = "DENY"


def grant_temporary_access(client_ip: str, port: int, protocol: str = "tcp",
                           ttl_seconds: int = DEFAULT_TTL_SECONDS,
                           *, session_id: str | None = None, sid: str = "unknown",
                           acl: str = ACL_FULL,
                           allowed_hosts: tuple[str, ...] | list[str] | None = None,
                           posture_signals: dict[str, bool] | None = None):
    """Open one leased hole for `client_ip`, scoped by `acl`.

    Returns the Session, or None when the ACL permits nothing. LIMITED with no
    hosts named grants nothing rather than everything — an empty allow-list is
    read as "no destinations", never as "unrestricted", so a Controller that
    omits the field cannot accidentally widen access.
    """
    acl = (acl or ACL_FULL).upper()

    if acl == ACL_DENY:
        status(log, "Grant refused - acl=DENY", client_ip=client_ip, port=port)
        return None

    hosts: tuple[str, ...] = tuple(allowed_hosts or ())

    if acl == ACL_LIMITED and not hosts:
        status(log, "Grant refused - acl=LIMITED named no hosts",
               client_ip=client_ip, port=port)
        return None

    if acl == ACL_FULL:
        # FULL ignores any host list: it reaches every destination by design.
        hosts = ()

    return TABLE.open(
        session_id=session_id or str(uuid.uuid4()),
        sid=sid,
        client_ip=client_ip,
        access_port=port,
        protocol=protocol,
        ttl_seconds=ttl_seconds,
        acl=acl,
        hosts=hosts,
        posture_signals=posture_signals,
    )
