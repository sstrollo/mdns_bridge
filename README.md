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
  to the calling process's lifetime. Probes for a conflict before
  claiming a name and defends it for as long as it's held (RFC 6762
  sections 8 and 9), with a pluggable policy for what to do about one.
- Built on OTP's own `inet_dns` for wire (de)coding, which already
  understands RFC 6762 (mDNS) framing - see `CONTRIBUTING.md`.

Status
------

Learning/bridging (phase 1) and publishing (phase 2, including probing,
conflict policies, and ongoing conflict defense) are implemented. The one
deliberate simplification: RFC 6762 8.2's simultaneous-probe tie-breaking
(two hosts probing the identical name at the identical instant, resolved
by a lexicographic comparison) is treated as a plain conflict rather than
implementing the actual tie-break comparison - see
[Publishing names](#publishing-names).

Requirements
------------

**OTP 27 or later** (CI tests 27-29). This is a hard requirement, not
just what's tested: `inet_dns:encode/2` and `decode/2` - the two-argument
forms that let a caller choose mDNS (`Mdns=true`) vs. classic
(`Mdns=false`) framing, which this app relies on throughout, both for
mDNS traffic and for the classic-DNS bridge - were only added to
`inet_dns`'s exported API in OTP 27. Earlier versions only export
`encode/1`/`decode/1`, which are hardcoded to `Mdns=true` internally with
no supported way to ask for classic framing instead - so the classic-DNS
bridge specifically cannot work correctly on OTP <27 via the public API.
(Confirmed by CI: `mdns_proto_tests`'s `inet_dns` round-trip tests fail
with `undef` on OTP 25/26, exactly as expected.)

The mDNS (de)coding also relies on record shapes vendored from OTP's
kernel-internal `inet_dns` module rather than reimplementing the wire
format - see `CONTRIBUTING.md` for what that means if you're touching
`include/mdns_dns.hrl`.

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

Pure-logic unit tests, plus `mdns_registry_probe_tests` which exercises
real probing/conflict/rename traffic over the loopback-visible multicast
group (no external peer needed - it plays both sides itself):

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
{ok, Ref, FinalName} = mdns:register("my-service.local", {192, 168, 1, 42}),
%% ... later, when you're done with it ...
ok = mdns:unregister(Ref).
```

By default this probes for a conflict first (RFC 6762 section 8: three
probe queries, 250ms apart, so this call typically takes at least
~750ms) before claiming the name, and keeps defending it against a
conflicting claim for as long as it's registered (RFC 6762 section 9).
`FinalName` is the name actually claimed - normally the same as what you
passed, but see `{rename, Fun}` below for when it isn't.

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
longer affects it, and it isn't treated as a conflict (that specific
combination is, by definition, something we ourselves already hold).

### Conflict handling

`on_conflict` controls what happens when a conflict is detected, both
during the initial probe and later while the name is held:

- `error` (the default) - fail the registration (`{error, {name_conflict,
  Name, ConflictingData}}`) or, if the conflict shows up later while the
  name is already held, withdraw it and send the owning process
  `{mdns_bridge_conflict, Ref, Name}`.
- `force` - claim the name regardless of a probe conflict, and never give
  it up on an ongoing one - always keep reasserting it instead.
- `{rename, Fun}` - probe time only: call `Fun(Name, Attempt)` (1-based
  `Attempt`) for a new name to try instead, and probe that one, up to
  `max_rename_attempts` (default 10) tries:

  ```erlang
  Fun = fun(Name, Attempt) -> Name ++ "-" ++ integer_to_list(Attempt) end,
  mdns:register("printer.local", Ip, #{on_conflict => {rename, Fun}}).
  %% -> {ok, Ref, "printer-1.local"} if "printer.local" was taken but
  %%    "printer-1.local" wasn't - deliberately not the "just append (2)
  %%    forever" approach some minimal implementations fall back to;
  %%    Fun decides the naming scheme.
  ```

  An ongoing conflict on a `{rename, Fun}` registration behaves like
  `error` (withdraw + notify) - it doesn't automatically re-probe and
  rename on its own while running; react to `{mdns_bridge_conflict, Ref,
  Name}` and call `register/2,3` again if you want that.

To skip probing entirely and claim a name immediately (today's original
"trust the caller" behavior, no ~750ms wait), pass `#{probe => false}` -
ongoing conflict defense still applies once registered either way.

One simplification worth knowing about: RFC 6762 8.2 covers two hosts
probing the *identical* name at the *identical* instant, resolved by a
lexicographic comparison of the two proposed records so one host wins
and the other backs off. This is treated as a plain conflict here (falls
through to whatever `on_conflict` says) rather than implementing that
comparison - the case is rare enough that the simplification is worth it.

Ongoing conflict defense is scoped to `{Name, Type}` as a whole, not to
an individual registration - if two different registrations legitimately
share a name (round-robin), a conflicting third party causes *all*
registrations under that name to be withdrawn together if defense has to
give up, since there's no way to tell "an outside squatter" from "our
own other registration" apart from the data already being one of our own
values.

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
- `max_rename_attempts` - cap on retries for `on_conflict => {rename,
  Fun}` before giving up with `{error, {name_conflict, _, _}}`.

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
- **Probing and ongoing defense are themselves unauthenticated**, like
  everything else in mDNS: anyone on the local segment can answer a probe
  (blocking a registration under the default `on_conflict => error`) or
  keep asserting a conflicting record (forcing repeated defense/give-up
  cycles). `on_conflict => force` sidesteps this for a name you're
  confident should always be yours, at the cost of no longer backing off
  from a real conflict either.
- **Network changes aren't detected automatically.** See
  [Network interface changes](#network-interface-changes) above.

Contributing
------------

See `CONTRIBUTING.md` for coding guidelines (formatting, dialyzer, tests)
before opening a PR.

License
-------

Apache-2.0 - see `LICENSE.md`.
