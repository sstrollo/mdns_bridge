mdns
=====

An mDNS listener/cache and `.local` DNS bridge, in Erlang.

Listens to mDNS traffic on the network (both passively and by actively
issuing its own mDNS queries), caches what it learns, and answers plain
unicast DNS queries for the `.local` domain on a configurable port - meant
to be the target an upstream resolver (e.g. Avassa's per-host nameserver)
forwards `.local` queries to.

This covers phase 1 only: learning names and serving A records. A phase 2
(registering and announcing arbitrary names/IPs via an Erlang API) is
planned but not yet implemented.

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
names, REFUSED for non-`.local` queries, and cache removal after a
goodbye/withdraw. Exits non-zero if anything fails.

Configuration
-------------

See `config/sys.config`:

- `interface` - interface name, literal IPv4 address, or `undefined` to
  auto-detect. Multi-homed hosts (e.g. an Avassa Edge Enforcer) should set
  this explicitly - mDNS is link-local per interface.
- `dns_port` / `dns_bind_ip` - where the classic-DNS bridge listens.
- `answer_ttl` - TTL cap applied to answers handed back over the bridge.
- `query_timeout_ms` - how long to wait for an on-demand mDNS answer on a
  cache miss before replying NXDOMAIN.
