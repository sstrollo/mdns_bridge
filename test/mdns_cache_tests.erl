-module(mdns_cache_tests).

-include_lib("eunit/include/eunit.hrl").

cache_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun insert_and_lookup/0,
            fun goodbye_removes_entry/0,
            fun near_expiry_reports_soon_to_expire/0,
            fun subscriber_is_notified_on_insert/0
        ]
    end}.

start() ->
    {ok, Pid} = mdns_cache:start_link(),
    Pid.

stop(Pid) ->
    gen_server:stop(Pid).

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
