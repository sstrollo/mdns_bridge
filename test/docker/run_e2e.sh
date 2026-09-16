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

echo "== test 4: a non-.local query is an empty NOERROR (not REFUSED) =="
RAW4=$(dig @127.0.0.1 -p 8053 +noall +comment example.com A)
echo "$RAW4" | grep -q 'status: NOERROR' && echo "$RAW4" | grep -q 'ANSWER: 0' && OK=1 || OK=0
check "non-.local query is empty NOERROR, not REFUSED (got: '$(echo "$RAW4" | grep status:)')" "$OK"

echo "== test 5: withdrawing the record (goodbye) removes it from our cache =="
kill "$PUBLISH_PID" 2>/dev/null
sleep 1
ANSWER3=$($DIG test-widget.local A)
[[ -z "$ANSWER3" ]] && OK=1 || OK=0
check "test-widget.local is gone after goodbye (got: '$ANSWER3')" "$OK"

echo "== test 6: inet_db can be pointed at this bridge for .local, with fallback for everything else =="
INET_DB_OUT=$(erl -noshell -eval "
inet_db:res_update_conf(),
Real = inet_db:res_option(nameservers) ++ inet_db:res_option(alt_nameservers),
inet_db:res_option(alt_nameservers, Real),
inet_db:res_option(nameservers, [{{127,0,0,1}, 8053}]),
inet_db:set_lookup([dns, native]),
Own = inet:gethostbyname(\"$HOSTNAME_LOCAL\"),
Unknown = inet:gethostbyname(\"nonexistent-blah.local\"),
io:format(\"own=~p unknown=~p~n\", [Own, Unknown]),
init:stop().
" 2>&1)
echo "$INET_DB_OUT"
echo "$INET_DB_OUT" | grep -q "own={ok," && echo "$INET_DB_OUT" | grep -q "unknown={error,nxdomain}" && OK=1 || OK=0
check "inet:gethostbyname/1 resolves own .local name via inet_db and NXDOMAINs an unknown one" "$OK"

echo "== test 7: mdns:register/2 (called from a separate Erlang node, as a real client would) publishes and withdraws a name =="
PUBLISH_OUT=$(erl -noshell -sname "tester$$" -setcookie mdnstest -eval "
{ok, Host} = inet:gethostname(),
Node = list_to_atom(\"mdnsapp@\" ++ Host),
pong = net_adm:ping(Node),
{ok, {{A,B,C,D}, _Netmask}} = rpc:call(Node, mdns_iface, resolve_with_netmask, [undefined]),
Ip = {A,B,C,(D+50) rem 256},
{ok, Ref} = rpc:call(Node, mdns, register, [\"e2e-publish.local\", Ip]),
timer:sleep(300),
DigWhileUp = os:cmd(\"dig @127.0.0.1 -p 8053 e2e-publish.local A +short\"),
io:format(\"ip=~p dig_while_up=~p~n\", [Ip, string:trim(DigWhileUp)]),
ok = rpc:call(Node, mdns, unregister, [Ref]),
timer:sleep(300),
DigAfterDown = os:cmd(\"dig @127.0.0.1 -p 8053 +noall +comment e2e-publish.local A\"),
Status = case re:run(DigAfterDown, \"status: ([A-Z]+)\", [{capture, all_but_first, list}]) of
    {match, [S]} -> S;
    nomatch -> \"NONE\"
end,
io:format(\"status_after_down=~p~n\", [Status]),
init:stop().
" 2>&1)
echo "$PUBLISH_OUT"
echo "$PUBLISH_OUT" | grep -qE 'dig_while_up="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' &&
    echo "$PUBLISH_OUT" | grep -q 'status_after_down="NXDOMAIN"' &&
    OK=1 || OK=0
check "mdns:register/2 publishes a resolvable name; mdns:unregister/1 withdraws it (NXDOMAIN after)" "$OK"

if [[ "$FAILED" -ne 0 ]]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
exit 0
