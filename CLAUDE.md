# Working on mdns_bridge

Project-specific guidance - read this before making changes.

## Before every commit

- Format all Erlang code: `rebar3 fmt`.
- Both of these must pass clean: `rebar3 eunit` and `rebar3 dialyzer`.

## Style rules

- **Binaries over strings.** Prefer `binary()` over lists/strings wherever
  practical - see "Names are binaries" below for the one confirmed
  exception and why.
- **Avoid ETS as long as possible.** See "ETS usage" below for the bar
  and the precedent of removing it where it didn't earn its keep.
- **Never use `~n`** in an `io:format`/`logger` format string - use a
  literal `\n` instead.
- **To print a term without letting it pretty-print across multiple
  lines, use `~0p` - not `~0w`.** `~0w` does not do what it looks like it
  should: `~w`'s field-width truncation collapses to *zero characters* at
  width 0, so `io:format("~0w\n", [Term])` silently prints nothing.
  `~0p` is what actually gives single-line output while still rendering
  strings/binaries readably (`~w` shows a binary as a raw byte list).
  Verified empirically - if this project's guidance to you ever says
  `~0w`, it means `~0p`.
- **Use `~b` for a value you know is an integer** (not `~p`/`~w`).
- **Prefer the `~"..."` sigil for binary string literals in new code**
  (e.g. `~"foo"`) over `<<"foo">>` - equivalent, escape-processed the
  same way (`~"a\nb"` contains a real newline, not literal backslash-n),
  and supported cleanly by this project's pinned erlfmt and OTP 27+
  floor - verified empirically (compiles, pattern-matches, round-trips
  through `rebar3 fmt` unchanged). `<<"...">>` is still fine/necessary
  for anything needing bit-syntax segments erlfmt/the sigil doesn't
  cover (explicit sizes, non-literal segments) - and comments/docs
  illustrating a binary value may keep using `<<"...">>` notation, since
  that's more universally recognizable prose, not a code literal choice.
- **Never use a bare `catch Expr`** - always `try ... catch ...` (a bare
  catch swallows exits/errors indiscriminately and makes error
  provenance hard to trace).
- **Legible but efficient.** This app's gen_servers run indefinitely -
  avoid needless intermediate terms on genuinely hot paths (every
  incoming mDNS packet in `mdns_socket`, every classic-DNS bridge query
  in `mdns_dns_server`). Don't sacrifice readability for cycles that
  don't matter elsewhere.

## Names are binaries

Names and domain-shaped data (a PTR's target, a SRV's target host) are
binaries everywhere in this app - registry/cache keys, comparisons, and
the public API's return values (`mdns:register/2,3` and
`register_service/5,6`'s `FinalName`) are all `binary()`.

The one confirmed exception: OTP's `inet_dns` (kernel-internal, vendored
via `include/mdns_dns.hrl`) requires a plain Erlang list for any
domain-name-shaped field - confirmed empirically, not assumed: a binary
domain crashes `encode/2` with `function_clause` in
`inet_dns:name2labels/1`, and `decode/2` always hands one back
regardless of what was encoded. This conversion happens *only* at the
wire-boundary functions in `mdns_proto.erl` (`to_domain/1`,
`to_wire_data/2`, `from_wire_data/2`) - everywhere else, names and
domain-shaped data are binaries. TXT record strings are not subject to
this: `inet_dns:encode/2` accepts binaries for those directly (verified)
- only the decode side needs converting back to our own binary form.

Before assuming some other stdlib/OTP function "needs a list," verify
empirically (a real shell, not memory) rather than assume - this
constraint turned out to be much narrower than it first looked.

## ETS usage

Avoid ETS unless it's genuinely earning its keep. The bar: many
concurrent readers (potentially from many different processes) and a
write path already funneled through a single owning gen_server, where
routing reads through that gen_server instead would create real
contention.

Two ETS-backed pub/sub tables (`mdns_cache`'s waiter table,
`mdns_socket`'s probe-watcher table) were both replaced with a monitored
`gen_server:call` / plain gen_server state after review found they
didn't meet that bar: subscribe/unsubscribe happened at most once per
operation (a cache miss, a probe cycle), never a hot path, so there was
nothing to gain from bypassing the gen_server - and the ETS version had
real correctness costs (a crash between subscribe/unsubscribe leaked the
row forever; a stray message could land in the caller's mailbox after
it had already returned via a different path).

The two ETS tables that remain, `mdns_cache_tab` and `mdns_registry_tab`,
meet the bar: both are read on the genuinely hot path (every incoming
mDNS packet, every classic-DNS bridge query - the latter from
potentially many concurrent short-lived processes, one per request, up
to `dns_rate_limit_per_second`) with writes already serialized through
one gen_server - the textbook single-writer/many-reader case ETS exists
for.

## Requirements

OTP 27+ is a hard requirement, not just what's tested:
`inet_dns:encode/2`/`decode/2`'s two-argument (mDNS-aware) forms only
exist from OTP 27 onward. CI matrix: OTP 27, 28, 29.
