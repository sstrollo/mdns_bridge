-module(mdns_query_tests).

-include_lib("eunit/include/eunit.hrl").

%% mdns_socket:send_query/2 is a gen_server:cast, which never fails even
%% when nothing is registered to receive it - so resolve/3's cache-miss
%% path is fully testable without a real mdns_socket/UDP socket; it just
%% times out (or is woken by a later insert_many/1) exactly as it would
%% with a real socket sending a query nobody answers.

query_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun registry_answer_takes_precedence_over_cache/0,
            fun cache_hit_returns_immediately/0,
            fun cache_miss_times_out/0,
            fun cache_miss_wakes_up_on_a_later_insert/0
        ]
    end}.

start() ->
    {ok, CachePid} = mdns_cache:start_link(),
    {ok, RegistryPid} = mdns_registry:start_link(),
    [CachePid, RegistryPid].

stop(Pids) ->
    [gen_server:stop(Pid) || Pid <- lists:reverse(Pids)].

registry_answer_takes_precedence_over_cache() ->
    {ok, Ref, _} = mdns:register("query-precedence.local", {10, 0, 0, 1}, #{
        validate => false, probe => false
    }),
    ok = mdns_cache:insert_many([{"query-precedence.local", a, {10, 0, 0, 99}, 120, false}]),
    ?assertMatch(
        {ok, [{{10, 0, 0, 1}, _}]}, mdns_query:resolve("query-precedence.local", a, 100)
    ),
    ok = mdns:unregister(Ref).

cache_hit_returns_immediately() ->
    ok = mdns_cache:insert_many([{"query-cache-hit.local", a, {10, 0, 0, 2}, 120, false}]),
    ?assertMatch({ok, [{{10, 0, 0, 2}, _}]}, mdns_query:resolve("query-cache-hit.local", a, 100)).

cache_miss_times_out() ->
    ?assertEqual({error, timeout}, mdns_query:resolve("query-never-appears.local", a, 100)).

%% Exercises the full path end to end: resolve/3's miss fires a
%% (harmlessly swallowed - no mdns_socket here) send_query, then blocks
%% in mdns_cache:await/3 until a later insert answers it.
cache_miss_wakes_up_on_a_later_insert() ->
    Self = self(),
    spawn(fun() ->
        Self ! {resolved, mdns_query:resolve("query-appears-late.local", a, 5000)}
    end),
    timer:sleep(100),
    ok = mdns_cache:insert_many([{"query-appears-late.local", a, {10, 0, 0, 3}, 120, false}]),
    receive
        {resolved, Result} -> ?assertMatch({ok, [{{10, 0, 0, 3}, _}]}, Result)
    after 1000 ->
        ?assert(false)
    end.
