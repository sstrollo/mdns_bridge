#!/bin/bash
set -uo pipefail

DIG="dig @127.0.0.1 -p 8053 +short +timeout=2 +tries=1"
FAILED=0

check() {
    local desc="$1"
    local ok="$2"
    if [[ "$ok" == "1" ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        FAILED=1
    fi
}

HOSTNAME_LOCAL="$(hostname).local"

echo "== waiting for avahi to announce ${HOSTNAME_LOCAL} =="
for _ in $(seq 1 20); do
    avahi-resolve-host-name -4 "$HOSTNAME_LOCAL" >/dev/null 2>&1 && break
    sleep 1
done

echo "== test 1: resolve own hostname from the passively-observed cache =="
ANSWER1=$($DIG "$HOSTNAME_LOCAL" A)
[[ -n "$ANSWER1" ]] && OK=1 || OK=0
check "own hostname ($HOSTNAME_LOCAL) resolves to an IPv4 address (got: '$ANSWER1')" "$OK"

echo "== test 2: on-demand resolve of a name not seen before =="
avahi-publish -a test-widget.local 10.1.2.3 >/tmp/avahi-publish.log 2>&1 &
PUBLISH_PID=$!
sleep 1
ANSWER2=$($DIG test-widget.local A)
[[ "$ANSWER2" == "10.1.2.3" ]] && OK=1 || OK=0
check "test-widget.local resolves to 10.1.2.3 (got: '$ANSWER2')" "$OK"

echo "== test 3: unknown .local name is NXDOMAIN, not a hang or crash =="
STATUS=$(dig @127.0.0.1 -p 8053 +noall +comment nonexistent-thing.local A | grep -o 'status: [A-Z]*')
[[ "$STATUS" == "status: NXDOMAIN" ]] && OK=1 || OK=0
check "unknown name gives NXDOMAIN (got: '$STATUS')" "$OK"

echo "== test 4: a non-.local query is REFUSED =="
STATUS2=$(dig @127.0.0.1 -p 8053 +noall +comment example.com A | grep -o 'status: [A-Z]*')
[[ "$STATUS2" == "status: REFUSED" ]] && OK=1 || OK=0
check "non-.local query is REFUSED (got: '$STATUS2')" "$OK"

echo "== test 5: withdrawing the record (goodbye) removes it from our cache =="
kill "$PUBLISH_PID" 2>/dev/null
sleep 1
ANSWER3=$($DIG test-widget.local A)
[[ -z "$ANSWER3" ]] && OK=1 || OK=0
check "test-widget.local is gone after goodbye (got: '$ANSWER3')" "$OK"

if [[ "$FAILED" -ne 0 ]]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
exit 0
