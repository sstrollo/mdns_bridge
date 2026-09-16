#!/bin/bash
set -uo pipefail

mkdir -p /var/run/dbus
dbus-daemon --system --fork
avahi-daemon --daemonize --no-chroot

# Erlang distribution (used by run_e2e.sh to call mdns:register/2,3 on
# the running node from a separate process, the same way a real client
# app would) needs this container's own hostname to resolve.
grep -q "$(hostname)" /etc/hosts || echo "127.0.0.1 $(hostname)" >>/etc/hosts

cd /app
erl -noshell -sname mdnsapp -setcookie mdnstest -pa _build/default/lib/mdns_bridge/ebin \
    -config config/sys \
    -eval 'application:ensure_all_started(mdns_bridge), timer:sleep(infinity).' &
MDNS_PID=$!

# Give the app a moment to join the multicast group and open the bridge port.
sleep 2

exec /usr/local/bin/run_e2e.sh
