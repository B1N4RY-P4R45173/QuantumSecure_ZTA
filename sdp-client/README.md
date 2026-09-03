# SDP Client (Initiating Host)

**Status: not yet implemented — planned for week 4.**

The client-side agent. Authenticates to the [controller](../sdp-controller/),
receives a signed authorization, then knocks on the
[gateway](../sdp-gateway/) with a Single Packet Authorization before
connecting to a protected resource.

## Planned responsibilities

| Capability | Week | Notes |
|---|---|---|
| Controller authentication | 4 | Obtain a signed, short-lived authorization token |
| Device posture reporting | 4 | Supply the MDM-style signals the trust algorithm consumes |
| SPA packet construction | 4 | Single encrypted UDP packet: HMAC + nonce + timestamp + requested service |
| Connection handoff | 4 | After the pinhole opens, hand off to the native client (`ssh`, browser, etc.) |
| Token refresh | 5 | Re-authorize before TTL expiry to keep long sessions alive |

## Connection flow

```
1. client  ──── authenticate ────▶  controller
2. client  ◀─── signed authz ─────  controller
3. controller ── open pinhole ───▶  gateway
4. client  ──── SPA packet ──────▶  gateway
5. client  ──── normal traffic ──▶  gateway ──▶ resource
```

Steps 3 and 4 are both required: the controller's instruction authorizes the
*policy*, and the SPA packet proves *liveness and possession of the key* from
the actual source address.
