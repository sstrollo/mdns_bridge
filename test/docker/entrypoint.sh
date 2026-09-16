#!/bin/bash
set -uo pipefail

mkdir -p /var/run/dbus
dbus-daemon --system --fork
avahi-daemon --daemonize --no-chroot

cd /app
erl -noshell -pa _build/default/lib/mdns/ebin \
    -config config/sys \
    -eval 'application:ensure_all_started(mdns), timer:sleep(infinity).' &
MDNS_PID=$!

# Give the app a moment to join the multicast group and open the bridge port.
sleep 2

exec /usr/local/bin/run_e2e.sh
