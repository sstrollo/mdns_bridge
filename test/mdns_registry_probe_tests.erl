-module(mdns_registry_probe_tests).

-include_lib("eunit/include/eunit.hrl").

%% Unlike mdns_registry_tests, these actually probe over the wire (real
%% mDNS multicast traffic), so this fixture starts mdns_cache and
%% mdns_socket too - and each test genuinely costs the real probe timing
%% (~750ms+ for a clean claim, more on a conflict/rename).

probe_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            {timeout, 10, fun probes_and_claims_an_uncontested_name/0},
            {timeout, 10, fun conflict_fails_registration_by_default/0},
            {timeout, 10, fun force_claims_despite_conflict/0},
            {timeout, 20, fun rename_retries_under_a_new_name_until_uncontested/0}
        ]
    end}.

start() ->
    {ok, CachePid} = mdns_cache:start_link(),
    {ok, SocketPid} = mdns_socket:start_link(),
    {ok, RegistryPid} = mdns_registry:start_link(),
    [CachePid, SocketPid, RegistryPid].

stop(Pids) ->
    [gen_server:stop(Pid) || Pid <- lists:reverse(Pids)].

sibling_ip(Offset) ->
    {ok, {{A, B, C, D}, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {A, B, C, (D + Offset) rem 256}.

%% Spawns a background "other device" that joins the multicast group
%% itself and, on seeing a probe question for Name/Type, answers with
%% Data - i.e. behaves like a real existing owner reacting to our probe,
%% which is what a genuine conflict looks like on the wire (a one-shot
%% answer sent *before* we start probing wouldn't be seen at all, since
%% we only subscribe for the duration of the probe). Gives up and exits
%% on its own after a few seconds either way.
spawn_conflicting_responder(Name, Type, Data) ->
    spawn(fun() -> conflicting_responder_init(Name, Type, Data) end).

conflicting_responder_init(Name, Type, Data) ->
    {ok, {IfaceIp, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {ok, S} = gen_udp:open(5353, [
        binary,
        {active, false},
        {reuseaddr, true},
        {ip, {0, 0, 0, 0}},
        {add_membership, {{224, 0, 0, 251}, IfaceIp}},
        {multicast_if, IfaceIp}
    ]),
    conflicting_responder_loop(S, Name, Type, Data, 10).

conflicting_responder_loop(S, _Name, _Type, _Data, 0) ->
    gen_udp:close(S);
conflicting_responder_loop(S, Name, Type, Data, Left) ->
    case gen_udp:recv(S, 0, 1000) of
        {ok, {_Ip, _Port, Packet}} ->
            case inet_dns:decode(Packet, true) of
                {ok, {dns_rec, _Header, [{dns_query, Name, Type, _, _} | _], _, _, _}} ->
                    answer_as(S, Name, Type, Data),
                    gen_udp:close(S);
                _ ->
                    conflicting_responder_loop(S, Name, Type, Data, Left - 1)
            end;
        {error, timeout} ->
            gen_udp:close(S)
    end.

answer_as(S, Name, Type, Data) ->
    Header = {dns_header, 0, 1, 0, 1, 0, 0, 0, 0, 0},
    RR = {dns_rr, Name, Type, in, 0, 120, Data, undefined, "", true},
    Rec = {dns_rec, Header, [], [RR], [], []},
    gen_udp:send(S, {224, 0, 0, 251}, 5353, inet_dns:encode(Rec, true)).

probes_and_claims_an_uncontested_name() ->
    Ip = sibling_ip(20),
    {ok, Ref, "probe-clean.local"} = mdns:register("probe-clean.local", Ip),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for("probe-clean.local", a)),
    ok = mdns:unregister(Ref).

conflict_fails_registration_by_default() ->
    Ip = sibling_ip(21),
    Other = sibling_ip(22),
    spawn_conflicting_responder("probe-conflict.local", a, Other),
    ?assertMatch(
        {error, {name_conflict, "probe-conflict.local", Other}},
        mdns:register("probe-conflict.local", Ip)
    ),
    ?assertEqual([], mdns_registry:answers_for("probe-conflict.local", a)).

force_claims_despite_conflict() ->
    Ip = sibling_ip(23),
    Other = sibling_ip(24),
    spawn_conflicting_responder("probe-force.local", a, Other),
    {ok, Ref, "probe-force.local"} = mdns:register("probe-force.local", Ip, #{
        on_conflict => force
    }),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for("probe-force.local", a)),
    ok = mdns:unregister(Ref).

rename_retries_under_a_new_name_until_uncontested() ->
    Ip = sibling_ip(25),
    Other = sibling_ip(26),
    %% Only the first candidate name is contested.
    spawn_conflicting_responder("probe-rename.local", a, Other),
    RenameFun = fun(_Name, Attempt) -> "probe-rename-" ++ integer_to_list(Attempt) ++ ".local" end,
    {ok, Ref, FinalName} = mdns:register("probe-rename.local", Ip, #{
        on_conflict => {rename, RenameFun}
    }),
    ?assertEqual("probe-rename-1.local", FinalName),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(FinalName, a)),
    ?assertEqual([], mdns_registry:answers_for("probe-rename.local", a)),
    ok = mdns:unregister(Ref).
