-module(mdns_cache_tests).

-include_lib("eunit/include/eunit.hrl").

cache_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun insert_and_lookup/0,
            fun goodbye_removes_entry/0,
            fun near_expiry_reports_soon_to_expire/0,
            fun dump_reports_current_entries/0
        ]
    end}.

%% Own fixture (a fresh, empty table) - await/3's job is inherently about
%% timing/concurrency (a waiting caller, a competing insert, a dead
%% caller), so isolating it from whatever else shares cache_test_/0's
%% table keeps these unambiguous.
await_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun await_returns_immediately_for_an_already_cached_answer/0,
            fun await_times_out_when_nothing_arrives/0,
            fun await_wakes_up_on_a_later_matching_insert/0,
            fun await_is_not_woken_by_a_goodbye_with_nothing_left_to_report/0,
            fun a_dead_waiting_caller_does_not_leak/0
        ]
    end}.

%% Own fixture (a fresh, empty table) since eviction/flush reason about
%% *every* row in the table, and would otherwise see cache_test_/0's rows.
cache_flush_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun cache_flush_removes_stale_conflicting_entry/0,
            fun cache_flush_keeps_same_batch_entries/0
        ]
    end}.

max_entries_test_() ->
    {setup, fun start_with_small_cap/0, fun stop_and_restore_cap/1, fun(_) ->
        [fun oldest_entries_are_evicted_past_the_cap/0]
    end}.

%% Own fixture (a fresh, empty table) - print/1's job is just "don't
%% crash and don't lose data", regardless of what's sharing the table.
print_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [fun print_handles_every_record_shape_seen_on_a_real_lan/0]
    end}.

start() ->
    {ok, Pid} = mdns_cache:start_link(),
    Pid.

stop(Pid) ->
    gen_server:stop(Pid).

start_with_small_cap() ->
    application:set_env(mdns_bridge, cache_max_entries, 3),
    start().

stop_and_restore_cap(Pid) ->
    stop(Pid),
    application:unset_env(mdns_bridge, cache_max_entries).

insert_and_lookup() ->
    ok = mdns_cache:insert_many([{"a.local", a, {10, 0, 0, 1}, 120, false}]),
    [{{10, 0, 0, 1}, Ttl}] = mdns_cache:lookup("a.local", a),
    ?assert(Ttl =< 120 andalso Ttl > 0).

goodbye_removes_entry() ->
    ok = mdns_cache:insert_many([{"b.local", a, {10, 0, 0, 2}, 120, false}]),
    ?assertMatch([_], mdns_cache:lookup("b.local", a)),
    ok = mdns_cache:insert_many([{"b.local", a, {10, 0, 0, 2}, 0, false}]),
    ?assertEqual([], mdns_cache:lookup("b.local", a)).

near_expiry_reports_soon_to_expire() ->
    ok = mdns_cache:insert_many([{"c.local", a, {10, 0, 0, 3}, 5, false}]),
    ?assert(lists:member({"c.local", a}, mdns_cache:near_expiry(60))),
    ?assertNot(lists:member({"c.local", a}, mdns_cache:near_expiry(1))).

await_returns_immediately_for_an_already_cached_answer() ->
    ok = mdns_cache:insert_many([{"await-hit.local", a, {10, 0, 0, 40}, 120, false}]),
    ?assertMatch({ok, [{{10, 0, 0, 40}, _}]}, mdns_cache:await("await-hit.local", a, 1000)).

await_times_out_when_nothing_arrives() ->
    ?assertEqual({error, timeout}, mdns_cache:await("await-never-arrives.local", a, 100)).

%% The whole point of await/3: block, and get woken up by a *later*
%% insert - not polling, not a raw `receive` in the caller.
await_wakes_up_on_a_later_matching_insert() ->
    Self = self(),
    spawn(fun() ->
        Self ! {await_result, mdns_cache:await("await-wakes-up.local", a, 5000)}
    end),
    timer:sleep(100),
    ok = mdns_cache:insert_many([{"await-wakes-up.local", a, {10, 0, 0, 41}, 120, false}]),
    receive
        {await_result, Result} ->
            ?assertMatch({ok, [{{10, 0, 0, 41}, _}]}, Result)
    after 1000 ->
        ?assert(false)
    end.

%% A goodbye (Ttl=0) for the name a caller is waiting on touches it, but
%% leaves nothing to report - must not wake the waiter up with an empty
%% answer; it should keep waiting until either a real answer arrives or
%% it times out.
await_is_not_woken_by_a_goodbye_with_nothing_left_to_report() ->
    Self = self(),
    spawn(fun() ->
        Self ! {await_result, mdns_cache:await("await-goodbye-only.local", a, 300)}
    end),
    timer:sleep(50),
    ok = mdns_cache:insert_many([{"await-goodbye-only.local", a, {10, 0, 0, 42}, 0, false}]),
    receive
        {await_result, Result} ->
            ?assertEqual({error, timeout}, Result)
    after 1000 ->
        ?assert(false)
    end.

%% If the waiting process dies before an answer or its own timeout, the
%% monitor-based cleanup must remove it rather than leaking it in state
%% forever - sys:get_state/1 (not a shared record - the state record
%% isn't exported via a header, so read positionally) is the standard
%% way to check gen_server-internal state from a test.
a_dead_waiting_caller_does_not_leak() ->
    Pid = spawn(fun() -> mdns_cache:await("await-leak-check.local", a, infinity) end),
    timer:sleep(50),
    ?assertEqual(1, map_size(waiters_in_state())),
    exit(Pid, kill),
    timer:sleep(50),
    ?assertEqual(0, map_size(waiters_in_state())).

waiters_in_state() ->
    element(2, sys:get_state(mdns_cache)).

dump_reports_current_entries() ->
    ok = mdns_cache:insert_many([{"h.local", a, {10, 0, 0, 5}, 120, false}]),
    ?assertMatch(
        [#{name := "h.local", type := a, data := {10, 0, 0, 5}, ttl_remaining := _, age := _}],
        [E || #{name := "h.local"} = E <- mdns_cache:dump()]
    ).

cache_flush_removes_stale_conflicting_entry() ->
    ok = mdns_cache:insert_many([{"e.local", a, {10, 0, 0, 10}, 120, false}]),
    %% age the first entry past the 1s cache-flush grace window
    timer:sleep(1100),
    ok = mdns_cache:insert_many([{"e.local", a, {10, 0, 0, 11}, 120, true}]),
    ?assertMatch([{{10, 0, 0, 11}, _}], mdns_cache:lookup("e.local", a)).

cache_flush_keeps_same_batch_entries() ->
    %% A single flush spanning several records (e.g. round-robin A
    %% records announced together) must not have its own records
    %% delete each other.
    ok = mdns_cache:insert_many([
        {"f.local", a, {10, 0, 0, 20}, 120, true},
        {"f.local", a, {10, 0, 0, 21}, 120, true}
    ]),
    ?assertEqual(2, length(mdns_cache:lookup("f.local", a))).

%% Real mDNS traffic includes shapes beyond the plain-A-record case every
%% other test here uses: raw/opaque binaries for record types this app
%% doesn't specifically decode, numeric (not atom) type codes, PTR/TXT
%% string data, the "single empty string" TXT quirk, and SRV/AAAA tuples
%% of various arities - all seen on a real LAN (anonymized: none of this
%% is real device/network data). print/1 must handle all of it without
%% crashing or silently dropping anything.
%% Entries use the same shapes mdns_proto:extract_records/1 actually
%% produces from real traffic (binary Name, and - via from_wire_data/2 -
%% binary PTR/SRV/TXT data too), matching a real LAN's mix of record
%% types: a multi-entry TXT record with a real device's shape (~20
%% key=value strings, not a token example), real NSEC (type 47) byte
%% shapes (both a compressed and an uncompressed "next name" encoding -
%% see mdns_proto's describe_nsec/1), and a name containing genuine
%% multi-byte UTF-8 (RFC 6763 explicitly allows UTF-8 in these strings,
%% and it's common in practice - device/service names with accents,
%% emoji, etc.).
print_handles_every_record_shape_seen_on_a_real_lan() ->
    %% "café.local" as explicit bytes, not a literal in this file's own
    %% source encoding - keeps the test unambiguous about which bytes
    %% are actually being exercised.
    CafeName = <<"caf", 195, 169, ".local">>,
    Entries = [
        %% NSEC, compressed next-name pointer, asserting "srv, txt exist"
        {<<"printer1._http._tcp.local">>, 47, <<193, 59, 0, 5, 0, 0, 128, 0, 64>>, 59, false},
        %% NSEC, uncompressed next-name ("anon-device.local"), asserting
        %% "a exists"
        {<<"anon-device.local">>, 47,
            <<11, 97, 110, 111, 110, 45, 100, 101, 118, 105, 99, 101, 5, 108, 111, 99, 97, 108, 0,
                0, 1, 64>>,
            59, false},
        {<<"_http._tcp.local">>, ptr, <<"printer1._http._tcp.local">>, 4125, false},
        {<<"_services._dns-sd._udp.local">>, ptr, <<"_http._tcp.local">>, 4125, false},
        {<<"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.local">>, a, {10, 0, 0, 50}, 3937, false},
        {<<"host1.local">>, aaaa, {65152, 0, 0, 0, 1, 2, 3, 4}, 1394, false},
        {CafeName, a, {10, 0, 0, 77}, 120, false},
        {<<"70-35-60-63\\.1 device2._sleep-proxy._udp.local">>, srv,
            {0, 0, 61264, <<"device2.local">>}, 3660, false},
        {<<"70-35-60-63\\.1 device2._sleep-proxy._udp.local">>, txt, [<<>>], 3660, false},
        {<<"host3._device-info._tcp.local">>, txt, [<<"model=SomeModel,1@ECOLOR=111,111,111">>],
            1703, false},
        {<<"printer1._ipp._tcp.local">>, txt,
            [
                <<"txtvers=1">>,
                <<"qtotal=1">>,
                <<"ty=Example Printer">>,
                <<"product=(Example Printer)">>,
                <<"priority=25">>,
                <<"Color=F">>,
                <<"Duplex=T">>
            ],
            4125, false},
        {<<"50.0.0.10.in-addr.arpa">>, ptr, <<"host4.local">>, 1397, false},
        {<<"1.2.3.4.5.6.7.8.9.0.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa">>, ptr,
            <<"host1.local">>, 1397, false}
    ],
    ok = mdns_cache:insert_many(Entries),
    Path = "mdns_cache_print_test_" ++ integer_to_list(erlang:unique_integer([positive])),
    {ok, F} = file:open(Path, [write]),
    ok = mdns_cache:print(F),
    ok = file:close(F),
    {ok, Bin} = file:read_file(Path),
    ok = file:delete(Path),
    Text = binary_to_list(Bin),
    Needles = [
        "printer1._http._tcp.local",
        %% nsec: decoded, not a raw dump. "types=a\n" (not just
        %% "types=a") distinguishes this from a types=aaaa row nearby -
        %% "types=a" alone would also match as its prefix. ttl isn't
        %% checked exactly - it can tick down by 1 between insert and
        %% print depending on timing.
        "types=txt,srv",
        "anon-device.local 47 ttl=",
        "types=a\n",
        %% a/aaaa: a real address string via inet:ntoa/1, not a tuple
        "10.0.0.50",
        "fe80::1:2:3:4",
        %% a genuinely multi-byte UTF-8 name renders as the real
        %% characters, not mangled - checked as explicit bytes (see
        %% CafeName above), not a literal in this file's own encoding
        binary_to_list(<<CafeName/binary, " a ttl=">>),
        %% srv: labeled fields, unquoted target
        "priority=0 weight=0 port=61264 target=device2.local",
        "70-35-60-63\\.1 device2._sleep-proxy._udp.local",
        %% txt: unquoted; a real (multi-entry) TXT record one string per
        %% line rather than crammed onto the entry's own line
        "model=SomeModel,1@ECOLOR=111,111,111",
        "  txtvers=1",
        "  product=(Example Printer)",
        "  Duplex=T",
        %% ptr: just the unquoted target name
        "host4.local",
        "1.2.3.4.5.6.7.8.9.0.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
        integer_to_list(length(Entries)) ++ " entries"
    ],
    [?assert(string:find(Text, Needle) =/= nomatch) || Needle <- Needles],
    ok.

oldest_entries_are_evicted_past_the_cap() ->
    ok = mdns_cache:insert_many([{"g1.local", a, {1, 1, 1, 1}, 120, false}]),
    timer:sleep(5),
    ok = mdns_cache:insert_many([{"g2.local", a, {1, 1, 1, 2}, 120, false}]),
    timer:sleep(5),
    ok = mdns_cache:insert_many([{"g3.local", a, {1, 1, 1, 3}, 120, false}]),
    timer:sleep(5),
    %% cache_max_entries is 3 (start_with_small_cap/0): inserting a 4th
    %% must evict the oldest (g1) to stay at the cap.
    ok = mdns_cache:insert_many([{"g4.local", a, {1, 1, 1, 4}, 120, false}]),
    ?assertEqual([], mdns_cache:lookup("g1.local", a)),
    ?assertMatch([_], mdns_cache:lookup("g2.local", a)),
    ?assertMatch([_], mdns_cache:lookup("g3.local", a)),
    ?assertMatch([_], mdns_cache:lookup("g4.local", a)).
