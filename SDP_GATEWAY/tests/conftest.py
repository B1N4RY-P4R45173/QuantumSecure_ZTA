"""Import bootstrap for the Gateway's tests.

Mirrors the sys.path setup in SDP_GATEWAY/main.py: the component's own directory
becomes the import root and the project root is added so `shared` resolves.
"""

import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_COMPONENT_DIR = os.path.dirname(_TESTS_DIR)
_PROJECT_ROOT = os.path.dirname(_COMPONENT_DIR)

for path in (_PROJECT_ROOT, _COMPONENT_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

# Never let a test touch the real packet filter. firewall.rules decides its
# backend once at import time, so this has to be set before anything imports
# it — otherwise a suite run as root (or in the Gateway's own container, which
# holds CAP_NET_ADMIN) would insert live rules and leave them behind.
os.environ["GATEWAY_FORCE_DRY_RUN"] = "1"
