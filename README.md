mdns
=====

<!-- Update OWNER/REPO once this is pushed to GitHub. -->
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)

An embeddable mDNS server / gateway for Erlang: it listens to mDNS
traffic on the network, caches what it learns, and bridges `.local` name
resolution to plain unicast DNS - so anything that can talk DNS (a system
resolver, an internal forwarder, or Erlang's own `inet_db`) can resolve
`.local` names without speaking mDNS itself.

Features
--------

- Listens to mDNS multicast traffic (`224.0.0.251:5353`) and caches
  learned A records, both passively and by actively (re-)querying, so
  answers don't just go stale between the last time something announced
  itself.
- Bridges `.local` resolution to plain unicast DNS on a configurable
  port - point a system DNS forwarder (dnsmasq, systemd-resolved) or an
  internal per-host nameserver at it, or [wire it straight into Erlang's
  own resolver](#using-this-from-erlang-directly-inet_db) with no
  external forwarder needed at all.
- Built on OTP's own `inet_dns` for wire (de)coding, which already
  understands RFC 6762 (mDNS) framing - see `CONTRIBUTING.md`.

Status
------

This covers **phase 1**: learning names from mDNS traffic and serving A
records over classic DNS. A **phase 2** - registering names via an
Erlang API and announcing them (including addresses other than the
host's own) over mDNS - is planned but not yet implemented.

Requirements
------------

OTP 25 or later (CI tests 25-28). The mDNS (de)coding relies on record
shapes vendored from OTP's kernel-internal `inet_dns` module rather than
reimplementing the wire format - see `CONTRIBUTING.md` for what that
means if you're touching `include/mdns_dns.hrl`.

Build
-----

    $ rebar3 compile

Run
---

    $ rebar3 shell

This joins the mDNS multicast group (`224.0.0.251:5353`) on the interface
configured in `config/sys.config` (`interface`; defaults to auto-picking
the first non-loopback IPv4 interface) and starts the `.local` DNS bridge
on the configured `dns_port` (default `8053`).

Try it:

    $ dig @127.0.0.1 -p 8053 some-device.local A

Test
----

Pure-logic unit tests:

    $ rebar3 eunit

End-to-end test, in a throwaway container with a real avahi-daemon acting
as an mDNS peer (see `test/docker/`):

    $ docker build -t mdns-test -f test/docker/Dockerfile .
    $ docker run --rm mdns-test

The container starts avahi-daemon and the app together, then runs
`test/docker/run_e2e.sh`, which exercises: resolving the container's own
avahi-announced hostname from the passive cache, on-demand resolution of a
name published after the app started, NXDOMAIN for unknown `.local`
names, an empty NOERROR answer for non-`.local` queries, cache removal
after a goodbye/withdraw, and the `inet_db` integration described below.
Exits non-zero if anything fails.

See `CONTRIBUTING.md` for the full set of checks (formatting, dialyzer,
tests) a change needs to pass - the same ones CI runs on every push.

Using this from Erlang directly (`inet_db`)
--------------------------------------------

You don't need any OS-level DNS forwarding to make plain Erlang code
resolve `.local` names - `inet:gethostbyname/1` (and anything built on
it, like `gen_tcp:connect/3`) can be pointed at this bridge directly by
configuring `inet_db`, Erlang's own resolver configuration, at runtime:

```erlang
%% inet_db reads /etc/resolv.conf lazily, on the first dns-method lookup
%% a node ever does - if we read/override `nameservers` before that
%% happens, it gets clobbered right back to the real resolv.conf value on
%% the next lookup. Force it to load now, before we touch anything.
inet_db:res_update_conf(),

%% Keep whatever real nameservers this node already picked up from
%% /etc/resolv.conf, and move them to the fallback list.
Real = inet_db:res_option(nameservers) ++ inet_db:res_option(alt_nameservers),
inet_db:res_option(alt_nameservers, Real),

%% Query our bridge first.
inet_db:res_option(nameservers, [{{127, 0, 0, 1}, 8053}]),

%% Make sure the `dns` lookup method (Erlang's own resolver, as opposed
%% to the OS's) is actually consulted.
inet_db:set_lookup([dns, native]).
```

With that in place, `inet:gethostbyname("some-device.local")` is answered
by this app, and `inet:gethostbyname("example.com")` (or any other
non-`.local` name) transparently falls through to the real nameservers
you moved into `alt_nameservers` - so this doesn't take over DNS
resolution for the whole node, just `.local`.

If you'd rather not touch global resolver state, `inet_res` also accepts
`nameservers` as a per-call option, which skips `inet_db` entirely:

```erlang
inet_res:gethostbyname("some-device.local", inet, [{nameservers, [{{127, 0, 0, 1}, 8053}]}], 2000).
```

This only works because of a specific, easy-to-get-wrong detail of OTP's
resolver (`inet_res`): it moves from the `nameservers` list to the
`alt_nameservers` list on NXDOMAIN or on an empty-but-OK (NOERROR, no
answers) reply, but *not* on REFUSED - REFUSED is treated as a final
answer. That's why this server never replies REFUSED for anything (an
earlier version did, for names outside `.local`, and it quietly broke
this exact setup): everything outside `.local` gets an empty NOERROR
instead, which is what makes the fallback to your real resolver work.

Configuration
-------------

See `config/sys.config`:

- `interface` - interface name, literal IPv4 address, or `undefined` to
  auto-detect. Multi-homed hosts should set this explicitly - mDNS is
  link-local per interface.
- `dns_port` / `dns_bind_ip` - where the classic-DNS bridge listens.
- `answer_ttl` - TTL cap applied to answers handed back over the bridge.
- `query_timeout_ms` - how long to wait for an on-demand mDNS answer on a
  cache miss before replying NXDOMAIN.

Contributing
------------

See `CONTRIBUTING.md` for coding guidelines (formatting, dialyzer, tests)
before opening a PR.

License
-------

Apache-2.0 - see `LICENSE.md`.
