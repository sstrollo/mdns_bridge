Contributing
============

Coding guidelines
------------------

These are enforced in CI (`.github/workflows/ci.yml`) - a PR that fails
any of them won't merge:

1. **Formatting**: code must pass [erlfmt](https://github.com/WhatsApp/erlfmt)
   with this project's config (`rebar.config`). Run `rebar3 fmt` before
   committing; CI runs `rebar3 fmt --check` and fails on any diff.

2. **Types**: `rebar3 dialyzer` must pass with zero warnings. Add specs
   to new public functions - dialyzer's success typing is only as good
   as the specs it has to check against.

3. **Tests**: `rebar3 eunit` must pass. New behavior needs a test;
   bug fixes should include a test that would have caught the bug.
   Pure logic (wire-format helpers, cache expiry) gets a unit test;
   anything that needs a real mDNS peer on the wire goes in the Docker
   end-to-end harness (`test/docker/`, see the README).

Run all three locally before pushing:

```sh
rebar3 fmt
rebar3 dialyzer
rebar3 eunit
```

Project-specific notes
-----------------------

- `include/mdns_dns.hrl` vendors record shapes from OTP's kernel-internal
  `inet_dns` module (not published under `kernel/include`, so it can't be
  `-include_lib`'d directly). If you touch it, keep it in sync with the
  installed OTP's `kernel/src/inet_dns.hrl`, and don't rely on it having
  fields beyond what's already vendored without checking there first.
  `mdns_proto_tests` round-trips records through the real
  `inet_dns:encode/decode` specifically to catch this drifting on a new
  OTP release; don't remove those tests.
- Keep the mDNS wire layer (`mdns_socket`) and the pure protocol/cache
  logic (`mdns_proto`, `mdns_cache`) separate - it's what makes the pure
  logic unit-testable without a real socket or network.
- No comments explaining *what* code does - name things well instead.
  A comment earns its place by explaining a non-obvious *why* (a spec
  detail, a workaround, an invariant a reader could easily get wrong).

Releases
--------

Version scheme is `YY.MM.N` - two-digit year, two-digit month, and a
0-based counter for the Nth release cut that month (so the first release
in a given month is `.0`, a second the same month is `.1`, and so on).
Tags are named exactly the same as the release.

To cut one, tag the commit and push the tag:

```sh
git tag 26.09.0
git push origin 26.09.0
```

Pushing a tag matching that shape triggers
`.github/workflows/release.yml`, which re-validates the tagged commit
(compile, `erlfmt`, `eunit`, `dialyzer` - a release-time gate, not a
second full CI matrix run) and then publishes a GitHub Release for that
tag with auto-generated release notes. Nothing computes the next version
number for you - decide it yourself before tagging.
