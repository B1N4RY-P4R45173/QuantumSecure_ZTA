#!/usr/bin/env bash
# The screen the reviewer watches.
#
#   +---------------------------+---------------------------+
#   |  Gateway                  |  Controller               |
#   |  SPA, firewall, sessions, |  trust score, detection,  |
#   |  proxy forwarding         |  policy, revocation       |
#   +---------------------------+---------------------------+
#   |  you type here:  ./demo/step 0 ... 6                   |
#   +--------------------------------------------------------+
#
# Both log panes are filtered down to the lines that carry the story. A
# reviewer cannot read an unfiltered log in real time, and a wall of INFO
# hides the three lines that matter.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SESSION="ztna-demo"

if ! command -v tmux >/dev/null; then
  echo "tmux is not installed:  sudo apt install -y tmux" >&2
  exit 1
fi

tmux kill-session -t "$SESSION" 2>/dev/null || true

GW_FILTER='SPA|Firewall|SESSION|Controller|PROXY|REVOKE|Gateway'
CT_FILTER='trust|Trust|QUARANT|DENIED|APPROVED|Decision|REVOKE|Policies'

tmux new-session  -d -s "$SESSION" -x "$(tput cols)" -y "$(tput lines)" -c "$ROOT"
tmux rename-window -t "$SESSION" "ztna"

# Top-left: the Gateway.
tmux send-keys -t "$SESSION" \
  "clear; echo '=== GATEWAY: knock, firewall, session, proxy ==='; \
   docker logs -f --tail 5 sdp-gateway 2>&1 | grep --line-buffered -E '$GW_FILTER'" C-m

# Top-right: the Controller.
tmux split-window -h -t "$SESSION" -c "$ROOT"
tmux send-keys -t "$SESSION" \
  "clear; echo '=== CONTROLLER: trust score, detection, decision ==='; \
   docker logs -f --tail 5 sdp-controller 2>&1 | grep --line-buffered -E '$CT_FILTER'" C-m

# Bottom: the driver pane, full width, where you work.
tmux select-pane -t "$SESSION".0
tmux split-window -v -t "$SESSION" -l 60% -f -c "$ROOT"
tmux send-keys -t "$SESSION" "clear; ./demo/step" C-m

tmux select-pane -t "$SESSION".2
tmux attach -t "$SESSION"
