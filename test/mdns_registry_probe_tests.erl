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
            {timeout, 20, fun rename_retries_under_a_new_name_until_uncontested/0},
            {timeout, 10, fun auto_is_shorthand_for_appending_the_attempt_number/0},
            {timeout, 20, fun rename_does_not_compound_across_repeated_conflicts/0}
        ]
    end}.

%% register_service/5,6 probes SRV then TXT (see mdns_registry's
%% moduledoc); the PTR (both the per-type and meta-enumeration one) is
%% never probed, so there's no PTR-conflict test here - only SRV/TXT.
%% Each test below uses its own service type so the type-level PTR and
%% meta-PTR assertions can't be affected by another test's registration.
service_probe_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            {timeout, 10, fun probes_and_claims_an_uncontested_service/0},
            {timeout, 10, fun srv_conflict_fails_registration_by_default/0},
            {timeout, 10, fun txt_conflict_fails_registration_by_default/0},
            {timeout, 10, fun force_claims_service_despite_conflict/0},
            {timeout, 20, fun rename_retries_service_under_a_new_label_until_uncontested/0},
            {timeout, 10, fun auto_is_shorthand_for_service_label_attempt_number/0}
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
    {ok, Ref, ~"probe-clean.local"} = mdns:register("probe-clean.local", Ip),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(~"probe-clean.local", a)),
    ok = mdns:unregister(Ref).

conflict_fails_registration_by_default() ->
    Ip = sibling_ip(21),
    Other = sibling_ip(22),
    spawn_conflicting_responder("probe-conflict.local", a, Other),
    ?assertMatch(
        {error, {name_conflict, ~"probe-conflict.local", Other}},
        mdns:register("probe-conflict.local", Ip)
    ),
    ?assertEqual([], mdns_registry:answers_for(~"probe-conflict.local", a)).

force_claims_despite_conflict() ->
    Ip = sibling_ip(23),
    Other = sibling_ip(24),
    spawn_conflicting_responder("probe-force.local", a, Other),
    {ok, Ref, ~"probe-force.local"} = mdns:register("probe-force.local", Ip, #{
        on_conflict => force
    }),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(~"probe-force.local", a)),
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
    ?assertEqual(~"probe-rename-1.local", FinalName),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(FinalName, a)),
    ?assertEqual([], mdns_registry:answers_for(~"probe-rename.local", a)),
    ok = mdns:unregister(Ref).

auto_is_shorthand_for_appending_the_attempt_number() ->
    Ip = sibling_ip(27),
    Other = sibling_ip(28),
    spawn_conflicting_responder("probe-auto.local", a, Other),
    {ok, Ref, FinalName} = mdns:register("probe-auto.local", Ip, #{on_conflict => auto}),
    ?assertEqual(~"probe-auto-1.local", FinalName),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(FinalName, a)),
    ok = mdns:unregister(Ref).

%% A second conflict must rename from the *original* name again
%% ("probe-compound-2.local"), not from the previous candidate
%% ("probe-compound-1.local-2") - see mdns_registry's handle_probe_conflict.
rename_does_not_compound_across_repeated_conflicts() ->
    Ip = sibling_ip(29),
    Other = sibling_ip(30),
    spawn_conflicting_responder("probe-compound.local", a, Other),
    spawn_conflicting_responder("probe-compound-1.local", a, Other),
    {ok, Ref, FinalName} = mdns:register("probe-compound.local", Ip, #{on_conflict => auto}),
    ?assertEqual(~"probe-compound-2.local", FinalName),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(FinalName, a)),
    ok = mdns:unregister(Ref).

probes_and_claims_an_uncontested_service() ->
    ServiceType = "_probeclean._tcp",
    ServiceTypeName = mdns_proto:service_type_name(ServiceType),
    {ok, Ref, FinalName} = mdns:register_service(
        "Probe Clean", ServiceType, 8080, [{"path", "/"}], "probetarget.local"
    ),
    ?assertEqual(mdns_proto:service_instance_name("Probe Clean", ServiceType), FinalName),
    ?assertMatch(
        [{{0, 0, 8080, ~"probetarget.local"}, _}], mdns_registry:answers_for(FinalName, srv)
    ),
    ?assertMatch([{[~"path=/"], _}], mdns_registry:answers_for(FinalName, txt)),
    ?assertMatch([{FinalName, _}], mdns_registry:answers_for(ServiceTypeName, ptr)),
    ?assertMatch(
        [{ServiceTypeName, _}],
        mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)
    ),
    ok = mdns:unregister(Ref),
    ?assertEqual([], mdns_registry:answers_for(FinalName, srv)),
    ?assertEqual([], mdns_registry:answers_for(ServiceTypeName, ptr)),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)).

%% spawn_conflicting_responder matches the *wire* packet's domain, which
%% is always a plain list (decode/2's own shape - see mdns_proto's
%% moduledoc) regardless of FullName's binary internal representation -
%% hence characters_to_list here. OtherSrv/OtherTxt, similarly, are what
%% the responder puts on the wire (list-shaped, like any raw dns_rr
%% data); what our own code reports as the conflicting Data has already
%% gone through mdns_proto:extract_watched_records/1's binary
%% normalization, so the assertions expect the binary-converted form.
srv_conflict_fails_registration_by_default() ->
    ServiceType = "_probesrvconflict._tcp",
    FullName = mdns_proto:service_instance_name("Probe Srv Conflict", ServiceType),
    OtherSrv = {0, 0, 9999, "othertarget.local"},
    spawn_conflicting_responder(unicode:characters_to_list(FullName), srv, OtherSrv),
    ?assertMatch(
        {error, {name_conflict, FullName, {srv, {0, 0, 9999, ~"othertarget.local"}}}},
        mdns:register_service("Probe Srv Conflict", ServiceType, 8080, [], "probetarget.local")
    ),
    ?assertEqual([], mdns_registry:answers_for(FullName, srv)).

txt_conflict_fails_registration_by_default() ->
    ServiceType = "_probetxtconflict._tcp",
    FullName = mdns_proto:service_instance_name("Probe Txt Conflict", ServiceType),
    OtherTxt = ["other=data"],
    spawn_conflicting_responder(unicode:characters_to_list(FullName), txt, OtherTxt),
    ?assertMatch(
        {error, {name_conflict, FullName, {txt, [~"other=data"]}}},
        mdns:register_service("Probe Txt Conflict", ServiceType, 8080, [], "probetarget.local")
    ),
    %% Nothing commits until both SRV and TXT probes clear, so the
    %% (uncontested) SRV must not have been claimed either.
    ?assertEqual([], mdns_registry:answers_for(FullName, srv)),
    ?assertEqual([], mdns_registry:answers_for(FullName, txt)).

force_claims_service_despite_conflict() ->
    ServiceType = "_probeforce._tcp",
    FullName = mdns_proto:service_instance_name("Probe Force", ServiceType),
    OtherSrv = {0, 0, 9999, "othertarget.local"},
    spawn_conflicting_responder(unicode:characters_to_list(FullName), srv, OtherSrv),
    {ok, Ref, FullName} = mdns:register_service(
        "Probe Force", ServiceType, 8080, [], "probetarget.local", #{on_conflict => force}
    ),
    ?assertMatch(
        [{{0, 0, 8080, ~"probetarget.local"}, _}], mdns_registry:answers_for(FullName, srv)
    ),
    ok = mdns:unregister(Ref).

%% Fun runs on the plain label ("Probe Rename"), not the full dotted
%% name - see mdns:register_service/6's doc.
rename_retries_service_under_a_new_label_until_uncontested() ->
    ServiceType = "_proberename._tcp",
    FullName = mdns_proto:service_instance_name("Probe Rename", ServiceType),
    OtherSrv = {0, 0, 9999, "othertarget.local"},
    spawn_conflicting_responder(unicode:characters_to_list(FullName), srv, OtherSrv),
    RenameFun = fun(Label, Attempt) -> Label ++ "-" ++ integer_to_list(Attempt) end,
    {ok, Ref, FinalName} = mdns:register_service(
        "Probe Rename",
        ServiceType,
        8080,
        [],
        "probetarget.local",
        #{on_conflict => {rename, RenameFun}}
    ),
    ?assertEqual(
        mdns_proto:service_instance_name("Probe Rename-1", ServiceType), FinalName
    ),
    ?assertMatch(
        [{{0, 0, 8080, ~"probetarget.local"}, _}], mdns_registry:answers_for(FinalName, srv)
    ),
    ?assertEqual([], mdns_registry:answers_for(FullName, srv)),
    ok = mdns:unregister(Ref).

auto_is_shorthand_for_service_label_attempt_number() ->
    ServiceType = "_probeauto._tcp",
    OtherSrv = {0, 0, 9999, "othertarget.local"},
    spawn_conflicting_responder(
        unicode:characters_to_list(mdns_proto:service_instance_name("Probe Auto", ServiceType)),
        srv,
        OtherSrv
    ),
    {ok, Ref, FinalName} = mdns:register_service(
        "Probe Auto", ServiceType, 8080, [], "probetarget.local", #{on_conflict => auto}
    ),
    ?assertEqual(
        mdns_proto:service_instance_name("Probe Auto-1", ServiceType), FinalName
    ),
    ok = mdns:unregister(Ref).
