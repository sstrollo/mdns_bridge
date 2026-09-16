mdns_bridge
===========

[![CI](https://github.com/sstrollo/mdns_bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/sstrollo/mdns_bridge/actions/workflows/ci.yml)

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
- Lets Erlang code [publish names](#publishing-names) over mDNS via
  `mdns:register/2,3` - including addresses other than the host's own
  (announcing on another device's behalf) - with the registration tied
  to the calling process's lifetime.
- Built on OTP's own `inet_dns` for wire (de)coding, which already
  understands RFC 6762 (mDNS) framing - see `CONTRIBUTING.md`.

Status
------

Both halves described above are implemented: learning/bridging (phase 1)
and publishing (phase 2). Deliberately out of scope for now: RFC 6762
probing and conflict resolution - registrations are announced trusting
the caller that the name is meant to be unique, rather than probing for
a live conflict and negotiating over it. See
[Publishing names](#publishing-names) for what that means in practice
and what the extension point for it will look like.

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

The container starts avahi-daemon and the app together (as a named,
distributed Erlang node), then runs `test/docker/run_e2e.sh`, which
exercises: resolving the container's own avahi-announced hostname from
the passive cache, on-demand resolution of a name published after the
app started, NXDOMAIN for unknown `.local` names, an empty NOERROR answer
for non-`.local` queries, cache removal after a goodbye/withdraw, the
`inet_db` integration described below, and `mdns:register/2,3` /
`unregister/1` called from a separate Erlang node (the same way an
actual client application would) publishing and then withdrawing a name.
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

Publishing names
----------------

`mdns:register/2,3` announces a `.local` name over mDNS on behalf of the
calling process:

```erlang
{ok, Ref} = mdns:register("my-service.local", {192, 168, 1, 42}),
%% ... later, when you're done with it ...
ok = mdns:unregister(Ref).
```

The registration is tied to the calling process: if it exits without
calling `unregister/1`, the name is withdrawn automatically (a goodbye
packet is sent), so nothing stays announced longer than whatever wanted
it published. Once registered, the name resolves both reactively (a real
mDNS query on the wire gets a real mDNS answer) and through this app's
own classic-DNS bridge - and a registered name is always answered from
the registry, taking priority over anything merely overheard on the
network for the same name (see
[Security considerations](#security-considerations)).

By default, the address must be on the same subnet as the configured
`interface` - a sanity check, since this app's own single interface is
what it actually announces on. To publish an address that isn't (for
example, announcing a name on behalf of some other device on the LAN
that doesn't speak mDNS itself), pass `#{validate => false}`:

```erlang
mdns:register("other-device.local", {192, 168, 1, 99}, #{validate => false}).
```

Registering the same `{name, address}` again - from the same process or
a different one - takes over the registration; the previous owner no
longer affects it. This app does not implement RFC 6762 probing or
defend a name against a conflicting claim from elsewhere on the network:
it trusts that whatever calls `register/2,3` already knows the name is
meant to be unique. If that ever needs to change, the natural extension
point is a `conflict` (or similarly named) option to `register/3` with
policies like `error` (fail if already probed as in use elsewhere),
`force` (claim it regardless), or a rename callback - rather than the
"just append `(2)` to the name" approach some minimal implementations
fall back to.

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
- `dns_rate_limit_per_second` - cap on classic-DNS bridge requests acted
  on per second (`infinity` to disable); see
  [Security considerations](#security-considerations).
- `publish_ttl` - TTL announced for names registered via
  `mdns:register/2,3`.
- `publish_reannounce_ms` - how often to re-announce every currently
  registered name, so caches elsewhere on the network stay fresh.
- `cache_max_entries` - cap on distinct records learned from the
  network; oldest entries are evicted once over it.

Network interface changes
--------------------------

This app resolves the configured interface's address once, at startup,
and does not watch for it changing (a DHCP renewal, a link up/down
event). That's the embedding system's job - call `mdns:interface_changed/0`
when you detect one:

```erlang
mdns:interface_changed().
```

This rejoins the mDNS multicast group on the new address if it changed,
and revalidates future registrations against the new subnet. It does not
touch existing registrations - re-register anything that should now be
announced under a different address.

Security considerations
------------------------

- **mDNS has no authentication.** Anything on the local network segment
  can announce a record for any name. A registered name (via
  `mdns:register/2,3`) is always answered from this app's own registry,
  taking priority over anything else the network says about that name -
  but a name this app merely *learns* by listening remains
  trust-on-first-use, bounded by RFC 6762 cache-flush handling and
  `cache_max_entries` rather than unbounded. Don't feed the classic-DNS
  bridge's answers for names you don't control into anything that makes
  security-sensitive decisions without independent verification.
- **The classic-DNS bridge answers whoever can reach it.** `dns_bind_ip`
  defaults to `{0,0,0,0}` (all interfaces, not just localhost). Bind it
  to `127.0.0.1` or a trusted interface if it shouldn't be reachable
  from the wider LAN; `dns_rate_limit_per_second` bounds how much it can
  be used to spawn processes or trigger outbound mDNS queries either way.
- **`mdns:register/2,3` has no authorization.** Any Erlang code running
  on the same node can publish, or take over, any name. Don't expose the
  node via unrestricted distributed Erlang to untrusted peers.
- **Network changes aren't detected automatically.** See
  [Network interface changes](#network-interface-changes) above.

Contributing
------------

See `CONTRIBUTING.md` for coding guidelines (formatting, dialyzer, tests)
before opening a PR.

License
-------

Apache-2.0 - see `LICENSE.md`.
