-module(mdns_cache_tests).

-include_lib("eunit/include/eunit.hrl").

cache_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun insert_and_lookup/0,
            fun goodbye_removes_entry/0,
            fun near_expiry_reports_soon_to_expire/0,
            fun subscriber_is_notified_on_insert/0,
            fun dump_reports_current_entries/0
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

subscriber_is_notified_on_insert() ->
    ok = mdns_cache:await_subscribe("d.local", a),
    ok = mdns_cache:insert_many([{"d.local", a, {10, 0, 0, 4}, 120, false}]),
    receive
        {mdns_answer, "d.local", a, [{{10, 0, 0, 4}, _}]} -> ok
    after 1000 ->
        ?assert(false)
    end.

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
print_handles_every_record_shape_seen_on_a_real_lan() ->
    Entries = [
        {"printer1._http._tcp.local", 47, <<193, 59, 0, 5, 0, 0, 128, 0, 64>>, 59, false},
        {"_http._tcp.local", ptr, "printer1._http._tcp.local", 4125, false},
        {"_services._dns-sd._udp.local", ptr, "_http._tcp.local", 4125, false},
        {"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.local", a, {10, 0, 0, 50}, 3937, false},
        {"host1.local", aaaa, {65152, 0, 0, 0, 1, 2, 3, 4}, 1394, false},
        {"70-35-60-63\\.1 device2._sleep-proxy._udp.local", srv, {0, 0, 61264, "Device2.local"},
            3660, false},
        {"70-35-60-63\\.1 device2._sleep-proxy._udp.local", txt, [[]], 3660, false},
        {"host3._device-info._tcp.local", txt, ["model=SomeModel,1@ECOLOR=111,111,111"], 1703,
            false},
        {"50.0.0.10.in-addr.arpa", ptr, "host4.local", 1397, false},
        {"1.2.3.4.5.6.7.8.9.0.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", ptr,
            "host1.local", 1397, false}
    ],
    ok = mdns_cache:insert_many(Entries),
    Path = "mdns_cache_print_test_" ++ integer_to_list(erlang:unique_integer([positive])),
    {ok, F} = file:open(Path, [write]),
    ok = mdns_cache:print(F),
    ok = file:close(F),
    {ok, Bin} = file:read_file(Path),
    ok = file:delete(Path),
    Text = binary_to_list(Bin),
    %% Not asserting a strict line count: io:format's ~p pretty-printer
    %% wraps a wide term (a multi-element tuple, a long binary) across
    %% several lines, so "one line per entry" doesn't hold in general -
    %% what matters is that every entry's data made it into the output
    %% intact, nothing crashed, and the summary count is right.
    Needles = [
        "printer1._http._tcp.local",
        "193,59",
        "0,5,0,0,128,0,64",
        "10,0,0,50",
        "65152",
        "61264",
        "Device2.local",
        "[[]]",
        "model=SomeModel,1@ECOLOR=111,111,111",
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
