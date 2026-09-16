mdns
=====

An mDNS listener/cache and `.local` DNS bridge, in Erlang.

Listens to mDNS traffic on the network (both passively and by actively
issuing its own mDNS queries), caches what it learns, and answers plain
unicast DNS queries for the `.local` domain on a configurable port - meant
to be the target an upstream resolver (a system DNS forwarder like
dnsmasq or systemd-resolved, an internal per-host nameserver, or Erlang's
own `inet_db` - see below) forwards `.local` queries to.

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
names, an empty NOERROR answer for non-`.local` queries, cache removal
after a goodbye/withdraw, and the `inet_db` integration described below.
Exits non-zero if anything fails.

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
