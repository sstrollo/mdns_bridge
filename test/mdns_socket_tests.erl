-module(mdns_socket_tests).

-include_lib("eunit/include/eunit.hrl").

socket_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun refresh_interface_is_a_noop_when_unchanged/0,
            fun probe_subscribe_and_unsubscribe_update_state/0,
            fun a_dead_probe_watcher_does_not_leak/0,
            fun non_latin1_name_does_not_crash_socket/0,
            fun malformed_inbound_packet_does_not_crash_socket/0,
            fun our_own_goodbyes_are_not_conflicts/0,
            fun withdraw_all_goodbyes_reach_the_wire/0
        ]
    end}.

%% Started in mdns_sup's order: mdns_socket hands every packet it
%% receives (including its own, via multicast loopback) to mdns_cache and
%% mdns_registry, so both must exist once anything is sent.
start() ->
    {ok, CachePid} = mdns_cache:start_link(),
    {ok, RegistryPid} = mdns_registry:start_link(),
    {ok, SocketPid} = mdns_socket:start_link(),
    [CachePid, RegistryPid, SocketPid].

stop(Pids) ->
    [gen_server:stop(Pid) || Pid <- lists:reverse(Pids)].

refresh_interface_is_a_noop_when_unchanged() ->
    %% Nothing about the configured interface has actually changed here,
    %% so this just exercises the re-resolve path without rejoining
    %% anything - mostly a guard against it crashing/hanging.
    ?assertEqual(ok, mdns_socket:refresh_interface()).

%% mdns_registry_probe_tests covers the real subscribe -> send_probe ->
%% {mdns_probe_seen, ...} -> unsubscribe cycle over the wire; this is
%% just the state bookkeeping itself (probe_watchers used to be a
%% separate ETS table - see mdns_socket's module doc).
probe_subscribe_and_unsubscribe_update_state() ->
    ok = mdns_socket:probe_subscribe("probe-state-check.local", a),
    ?assertEqual(1, map_size(probe_watchers_in_state())),
    ok = mdns_socket:probe_unsubscribe("probe-state-check.local", a),
    ?assertEqual(0, map_size(probe_watchers_in_state())).

%% A caller that crashes mid-probe (before it gets to call
%% probe_unsubscribe/2) must not leak its watcher entry forever - the
%% monitor-based cleanup this module gained when it moved off ETS.
a_dead_probe_watcher_does_not_leak() ->
    Pid = spawn(fun() ->
        ok = mdns_socket:probe_subscribe("probe-leak-check.local", a),
        receive
            stop -> ok
        end
    end),
    timer:sleep(50),
    ?assertEqual(1, map_size(probe_watchers_in_state())),
    exit(Pid, kill),
    timer:sleep(50),
    ?assertEqual(0, map_size(probe_watchers_in_state())).

%% The shutdown path (mdns_app:prep_stop/1): withdraw_all/0 followed by
%% sync/0 must have put a goodbye (TTL 0) for each registered record on
%% the wire by the time sync/0 returns - observed here by a second
%% member of the multicast group.
withdraw_all_goodbyes_reach_the_wire() ->
    Name = ~"goodbye-on-shutdown.local",
    {ok, _Ref, Name} = mdns:register(Name, {10, 9, 9, 7}, #{probe => false, validate => false}),
    Listener = open_group_listener(),
    ok = mdns_registry:withdraw_all(),
    ok = mdns_socket:sync(),
    ?assert(saw_goodbye(Listener, binary_to_list(Name), 1000)),
    gen_udp:close(Listener).

open_group_listener() ->
    {ok, {IfaceIp, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {ok, S} = gen_udp:open(5353, [
        binary,
        {active, false},
        {reuseaddr, true},
        {ip, {0, 0, 0, 0}},
        {add_membership, {{224, 0, 0, 251}, IfaceIp}}
    ]),
    S.

saw_goodbye(S, Domain, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    saw_goodbye_until(S, Domain, Deadline).

saw_goodbye_until(S, Domain, Deadline) ->
    Left = Deadline - erlang:monotonic_time(millisecond),
    case Left > 0 andalso gen_udp:recv(S, 0, Left) of
        {ok, {_Ip, _Port, Packet}} ->
            case inet_dns:decode(Packet, true) of
                {ok, {dns_rec, _Header, _Qd, An, _Ns, _Ar}} ->
                    case [D || {dns_rr, D, a, in, _, 0, _, _, _, _} <- An, D =:= Domain] of
                        [] -> saw_goodbye_until(S, Domain, Deadline);
                        [_ | _] -> true
                    end;
                _ ->
                    saw_goodbye_until(S, Domain, Deadline)
            end;
        _ ->
            false
    end.

%% #state.probe_watchers, read positionally since the record isn't
%% shared via a header - sys:get_state/1 is a standard debug/testing
%% escape hatch (same technique used in mdns_cache_tests).
probe_watchers_in_state() ->
    element(4, sys:get_state(mdns_socket)).

%% A name containing a character above U+00FF (here U+4E2D, as learned
%% from the network and later re-queried by mdns_query's refresh sweep)
%% must be sent, not crash this gen_server in inet_dns:encode/2.
non_latin1_name_does_not_crash_socket() ->
    Pid = whereis(mdns_socket),
    ok = mdns_socket:send_query(<<228, 184, 173, ".local">>, a),
    ok = mdns_socket:announce(<<228, 184, 173, ".local">>, a, [{{10, 0, 0, 1}, 0}]),
    %% A call after the casts is answered only once they've been handled.
    ok = mdns_socket:refresh_interface(),
    ?assertEqual(Pid, whereis(mdns_socket)).

%% inet_dns:decode/2 raises (rather than returning {error, _}) on some
%% malformed input - this 4-byte datagram is one such case. Sent to the
%% multicast group (so it reaches our socket regardless of any other
%% mDNS responder sharing port 5353 on this host), it must be dropped,
%% not take the gen_server down.
malformed_inbound_packet_does_not_crash_socket() ->
    Pid = whereis(mdns_socket),
    {ok, {IfaceIp, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {ok, S} = gen_udp:open(0, [binary, {multicast_if, IfaceIp}, {multicast_loop, true}]),
    ok = gen_udp:send(S, {224, 0, 0, 251}, 5353, <<0, 0, 132, 0>>),
    ok = gen_udp:send(S, {224, 0, 0, 251}, 5353, <<>>),
    ok = gen_udp:send(S, {224, 0, 0, 251}, 5353, <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>),
    gen_udp:close(S),
    timer:sleep(100),
    ?assertEqual(Pid, whereis(mdns_socket)),
    %% ...and it's still processing packets afterwards.
    ok = mdns_socket:refresh_interface().

%% Two sibling registrations under one name (round-robin); the sibling
%% is registered and withdrawn twice in quick succession. Each of its
%% goodbyes loops back through this socket as an answer for the name
%% with data that is no longer one of our registered values - which must
%% not count as an ongoing conflict, or the second one (inside
%% mdns_registry's defense grace window) would make it give up the
%% registration that's still legitimately held.
our_own_goodbyes_are_not_conflicts() ->
    Name = "goodbye-sibling.local",
    Opts = #{probe => false, validate => false},
    {ok, Keeper, _} = mdns:register(Name, {10, 9, 9, 2}, Opts),
    {ok, Sibling1, _} = mdns:register(Name, {10, 9, 9, 1}, Opts),
    timer:sleep(100),
    ok = mdns:unregister(Sibling1),
    timer:sleep(100),
    {ok, Sibling2, _} = mdns:register(Name, {10, 9, 9, 3}, Opts),
    timer:sleep(100),
    ok = mdns:unregister(Sibling2),
    timer:sleep(200),
    ?assertMatch([{{10, 9, 9, 2}, _}], mdns_registry:answers_for(~"goodbye-sibling.local", a)),
    receive
        {mdns_bridge_conflict, Keeper, _} = Msg -> error({spurious_conflict, Msg})
    after 0 -> ok
    end,
    ok = mdns:unregister(Keeper).
