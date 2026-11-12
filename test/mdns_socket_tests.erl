-module(mdns_socket_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_dns.hrl").

socket_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun refresh_interface_is_a_noop_when_unchanged/0,
            fun refresh_interface_survives_an_address_change_either_way/0,
            fun probe_subscribe_and_unsubscribe_update_state/0,
            fun a_dead_probe_watcher_does_not_leak/0,
            fun non_latin1_name_does_not_crash_socket/0,
            fun malformed_inbound_packet_does_not_crash_socket/0,
            fun our_own_goodbyes_are_not_conflicts/0,
            fun withdraw_all_goodbyes_reach_the_wire/0,
            fun responses_are_only_believed_from_port_5353/0,
            fun records_inside_a_query_are_not_cached/0,
            fun our_own_records_are_not_cached/0
        ]
    end}.

%% Reactive answering (the responder side of RFC 6762/6763). Legacy
%% unicast queries - sent from an ephemeral port - are the easiest way
%% to observe an answer: it comes straight back to the querying socket.
responder_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun legacy_unicast_query_gets_a_capped_unicast_answer/0,
            fun any_query_returns_every_registered_type/0,
            fun ptr_answer_carries_srv_txt_and_a_as_additionals/0,
            {timeout, 10, fun multicast_answers_are_rate_limited_per_record/0}
        ]
    end}.

legacy_unicast_query_gets_a_capped_unicast_answer() ->
    {ok, Ref, Name} = mdns:register("legacy-q.local", {10, 9, 9, 21}, #{
        probe => false, validate => false
    }),
    Query = (mdns_proto:mdns_query(Name, a))#dns_rec{header = #dns_header{id = 4242}},
    {ok, Resp} = legacy_query(Query),
    #dns_rec{header = Header, qdlist = [Q], anlist = [RR]} = Resp,
    ?assertEqual(4242, Header#dns_header.id),
    ?assert(Header#dns_header.qr),
    ?assertEqual(binary_to_list(Name), Q#dns_query.domain),
    ?assertEqual(binary_to_list(Name), RR#dns_rr.domain),
    ?assertEqual({10, 9, 9, 21}, RR#dns_rr.data),
    %% RFC 6762 6.7: TTL capped at 10 for a legacy client, no cache-flush.
    ?assert(RR#dns_rr.ttl =< 10),
    ?assertNot(RR#dns_rr.func),
    ok = mdns:unregister(Ref).

any_query_returns_every_registered_type() ->
    {ok, Ref, Name} = mdns:register_service(
        "Any Svc", "_anysvc._tcp", 8080, [{"k", "v"}], "anyhost.local", #{probe => false}
    ),
    {ok, #dns_rec{anlist = An}} = legacy_query(mdns_proto:mdns_query(Name, any)),
    ?assertEqual([srv, txt], lists:sort([RR#dns_rr.type || RR <- An])),
    ok = mdns:unregister(Ref).

ptr_answer_carries_srv_txt_and_a_as_additionals() ->
    Opts = #{probe => false, validate => false},
    {ok, HostRef, _} = mdns:register("addl-host.local", {10, 9, 9, 22}, Opts),
    {ok, SvcRef, Instance} = mdns:register_service(
        "Addl Svc", "_addl._tcp", 8080, [], "addl-host.local", #{probe => false}
    ),
    {ok, #dns_rec{anlist = An, arlist = Ar}} = legacy_query(
        mdns_proto:mdns_query(~"_addl._tcp.local", ptr)
    ),
    ?assertMatch([#dns_rr{type = ptr}], An),
    ?assertEqual(binary_to_list(Instance), (hd(An))#dns_rr.data),
    ?assertEqual(
        lists:sort([
            {"addl-host.local", a}, {binary_to_list(Instance), srv}, {binary_to_list(Instance), txt}
        ]),
        lists:sort([{RR#dns_rr.domain, RR#dns_rr.type} || RR <- Ar])
    ),
    ok = mdns:unregister(SvcRef),
    ok = mdns:unregister(HostRef).

%% RFC 6762 section 6: the same record is multicast at most once per
%% second in response to queries - except to answer a probe. Observed by
%% a second member of the group.
multicast_answers_are_rate_limited_per_record() ->
    {ok, Ref, Name} = mdns:register("rate-limited.local", {10, 9, 9, 23}, #{
        probe => false, validate => false
    }),
    %% The announcement counts as a multicast of the record, and so does
    %% mdns_registry's follow-up announcement one second later.
    timer:sleep(2100),
    Listener = open_group_listener(),
    Query = inet_dns:encode(mdns_proto:mdns_query(Name, a), true),
    multicast_from(5353, Query),
    timer:sleep(100),
    multicast_from(5353, Query),
    ?assertEqual(1, count_answers(Listener, binary_to_list(Name), 600)),
    timer:sleep(1000),
    Probe = inet_dns:encode(mdns_proto:probe_query(Name, a, {10, 9, 9, 99}, 120), true),
    multicast_from(5353, Probe),
    timer:sleep(100),
    multicast_from(5353, Probe),
    ?assertEqual(2, count_answers(Listener, binary_to_list(Name), 600)),
    gen_udp:close(Listener),
    ok = mdns:unregister(Ref).

%% Multicasts Query from an ephemeral port - a legacy unicast query as
%% far as the responder is concerned - and returns the unicast answer
%% that comes back to the same socket.
legacy_query(Query) ->
    {ok, {IfaceIp, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {ok, S} = gen_udp:open(0, [
        binary, {active, false}, {multicast_if, IfaceIp}, {multicast_loop, true}
    ]),
    ok = gen_udp:send(S, {224, 0, 0, 251}, 5353, inet_dns:encode(Query, true)),
    Result =
        case gen_udp:recv(S, 0, 1000) of
            {ok, {_Ip, _Port, Packet}} -> inet_dns:decode(Packet, false);
            {error, _} = Err -> Err
        end,
    gen_udp:close(S),
    Result.

count_answers(S, Domain, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    count_answers_until(S, Domain, Deadline, 0).

count_answers_until(S, Domain, Deadline, Count) ->
    Left = Deadline - erlang:monotonic_time(millisecond),
    case Left > 0 andalso gen_udp:recv(S, 0, Left) of
        {ok, {_Ip, _Port, Packet}} ->
            case inet_dns:decode(Packet, true) of
                {ok, #dns_rec{header = #dns_header{qr = true}, anlist = An}} ->
                    Hits = [D || #dns_rr{domain = D, type = a} <- An, D =:= Domain],
                    count_answers_until(S, Domain, Deadline, Count + length(Hits));
                _ ->
                    count_answers_until(S, Domain, Deadline, Count)
            end;
        _ ->
            Count
    end.

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

%% Point the configured interface at the loopback address and back: a
%% real change of address, exercising both the leave (on an address the
%% socket may or may not be able to leave) and the join (loopback often
%% can't do multicast at all, so this may legitimately fail). Whatever
%% the OS says to each, the process must survive and be usable - and
%% restoring the config must get us back onto the original interface.
refresh_interface_survives_an_address_change_either_way() ->
    Pid = whereis(mdns_socket),
    Original = application:get_env(mdns_bridge, interface),
    application:set_env(mdns_bridge, interface, "127.0.0.1"),
    try
        ?assertMatch(R when R =:= ok; element(1, R) =:= error, mdns_socket:refresh_interface())
    after
        case Original of
            {ok, Value} -> application:set_env(mdns_bridge, interface, Value);
            undefined -> application:unset_env(mdns_bridge, interface)
        end
    end,
    ?assertEqual(Pid, whereis(mdns_socket)),
    ?assertEqual(ok, mdns_socket:refresh_interface()),
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

%% RFC 6762 section 6: a response from any source port other than 5353
%% must be ignored. Both packets below are identical and both reach our
%% socket via the group; only the one from port 5353 may land in the
%% cache.
responses_are_only_believed_from_port_5353() ->
    multicast_from(ephemeral, answer_packet(~"port-check-eph.local", {10, 9, 9, 11})),
    multicast_from(5353, answer_packet(~"port-check-5353.local", {10, 9, 9, 12})),
    timer:sleep(150),
    ?assertEqual([], mdns_cache:lookup(~"port-check-eph.local", a)),
    ?assertMatch([{{10, 9, 9, 12}, _}], mdns_cache:lookup(~"port-check-5353.local", a)).

%% A query's answer section is the querier's known-answer list (RFC 6762
%% 7.1), not an assertion by the record's owner - it must not be cached
%% even from port 5353.
records_inside_a_query_are_not_cached() ->
    Name = ~"known-answer.local",
    #dns_rec{anlist = An} = mdns_proto:mdns_answer(Name, a, [{{10, 9, 9, 14}, 120}]),
    Query = (mdns_proto:mdns_query(Name, a))#dns_rec{anlist = An},
    multicast_from(5353, inet_dns:encode(Query, true)),
    timer:sleep(150),
    ?assertEqual([], mdns_cache:lookup(Name, a)).

%% Our own announcements loop back through the group like anyone else's
%% answers; they're answered from the registry and must not also end up
%% in the cache (where mdns_query's refresh sweep would re-query them).
our_own_records_are_not_cached() ->
    {ok, Ref, Name} = mdns:register("own-not-cached.local", {10, 9, 9, 13}, #{
        probe => false, validate => false
    }),
    ok = mdns_socket:sync(),
    timer:sleep(150),
    ?assertEqual([], mdns_cache:lookup(Name, a)),
    ?assertMatch([{{10, 9, 9, 13}, _}], mdns_registry:answers_for(Name, a)),
    ok = mdns:unregister(Ref).

answer_packet(Name, Ip) ->
    inet_dns:encode(mdns_proto:mdns_answer(Name, a, [{Ip, 120}]), true).

%% Sends Packet to the group from a socket bound to Port (`ephemeral`
%% for any free one), looped back so our own socket receives it.
multicast_from(PortSpec, Packet) ->
    {ok, {IfaceIp, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    Port =
        case PortSpec of
            ephemeral -> 0;
            P -> P
        end,
    {ok, S} = gen_udp:open(Port, [
        binary,
        {reuseaddr, true},
        {ip, {0, 0, 0, 0}},
        {multicast_if, IfaceIp},
        {multicast_loop, true}
    ]),
    ok = gen_udp:send(S, {224, 0, 0, 251}, 5353, Packet),
    gen_udp:close(S).

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
    element(5, sys:get_state(mdns_socket)).

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
