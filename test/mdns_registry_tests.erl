-module(mdns_registry_tests).

-include_lib("eunit/include/eunit.hrl").

%% mdns_registry announces via mdns_socket:announce/3 (a gen_server cast,
%% which never fails even if the target isn't running), so these tests
%% don't need a real mdns_socket/UDP socket - just the registry itself.
%% All successful registrations here pass `probe => false` so they don't
%% need mdns_socket either (probing genuinely sends/receives mDNS
%% packets) - see mdns_registry_probe_tests for probing/conflict
%% coverage that does need a real socket.

registry_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun register_and_unregister/0,
            fun auto_withdraw_on_process_death/0,
            fun takeover_keeps_registration_alive/0,
            fun rejects_out_of_subnet_address_by_default/0,
            fun validate_false_allows_out_of_subnet_address/0,
            fun rejects_non_local_name/0,
            fun rejects_invalid_address_shape/0,
            fun rejects_out_of_range_address/0,
            fun rejects_non_boolean_validate_option_without_crashing/0,
            fun rejects_non_boolean_probe_option/0,
            fun rejects_invalid_on_conflict_option/0,
            fun accepts_auto_on_conflict_option/0,
            fun rejects_unknown_option_without_crashing/0,
            fun refresh_interface_leaves_registry_usable/0,
            fun ongoing_conflict_is_defended_once_then_given_up/0,
            fun ongoing_conflict_is_ignored_for_our_own_sibling_data/0,
            fun force_on_conflict_never_gives_up_ongoing_defense/0
        ]
    end}.

%% register_service/5,6 - all with probe => false, same rationale as
%% above; see mdns_registry_probe_tests for its probing/conflict coverage.
service_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun registers_ptr_srv_and_txt_together/0,
            fun empty_txt_kvs_publishes_one_empty_string/0,
            fun unregister_withdraws_the_whole_service/0,
            fun auto_withdraw_on_process_death_withdraws_the_whole_service/0,
            fun meta_ptr_is_reference_counted_across_same_type_services/0,
            fun target_host_need_not_be_separately_registered/0,
            fun rejects_bad_service_type/0,
            fun rejects_bad_port/0,
            fun rejects_non_local_target_host/0,
            fun rejects_validate_option_for_services/0
        ]
    end}.

service_local_target(N) ->
    "servicehost" ++ integer_to_list(N) ++ ".local".

registers_ptr_srv_and_txt_together() ->
    {ok, Ref, FinalName} = mdns_registry:register_service(
        "My Printer", "_http._tcp", 631, [{"path", "/"}], service_local_target(1), #{
            probe => false
        }
    ),
    ?assertEqual(~"my printer._http._tcp.local", FinalName),
    ?assertMatch(
        [{{0, 0, 631, ~"servicehost1.local"}, _}],
        mdns_registry:answers_for(FinalName, srv)
    ),
    ?assertMatch([{[~"path=/"], _}], mdns_registry:answers_for(FinalName, txt)),
    ?assertMatch(
        [{FinalName, _}], mdns_registry:answers_for(~"_http._tcp.local", ptr)
    ),
    ?assertMatch(
        [{~"_http._tcp.local", _}],
        mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)
    ),
    ok = mdns_registry:unregister(Ref).

empty_txt_kvs_publishes_one_empty_string() ->
    {ok, Ref, FinalName} = mdns_registry:register_service(
        "No Txt", "_http._tcp", 80, [], service_local_target(2), #{probe => false}
    ),
    ?assertMatch([{[<<>>], _}], mdns_registry:answers_for(FinalName, txt)),
    ok = mdns_registry:unregister(Ref).

unregister_withdraws_the_whole_service() ->
    {ok, Ref, FinalName} = mdns_registry:register_service(
        "Gone Soon", "_http._tcp", 80, [], service_local_target(3), #{probe => false}
    ),
    ok = mdns_registry:unregister(Ref),
    ?assertEqual([], mdns_registry:answers_for(FinalName, srv)),
    ?assertEqual([], mdns_registry:answers_for(FinalName, txt)),
    ?assertEqual([], mdns_registry:answers_for(~"_http._tcp.local", ptr)),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)).

auto_withdraw_on_process_death_withdraws_the_whole_service() ->
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, _Ref, FinalName} = mdns_registry:register_service(
            "Dying Service", "_http._tcp", 80, [], service_local_target(4), #{probe => false}
        ),
        Parent ! {registered, FinalName},
        receive
            stop -> ok
        end
    end),
    FinalName =
        receive
            {registered, F} -> F
        after 1000 -> ?assert(false)
        end,
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Mon, process, Pid, killed} -> ok
    after 1000 -> ?assert(false)
    end,
    timer:sleep(50),
    ?assertEqual([], mdns_registry:answers_for(FinalName, srv)),
    ?assertEqual([], mdns_registry:answers_for(~"_http._tcp.local", ptr)),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)).

meta_ptr_is_reference_counted_across_same_type_services() ->
    {ok, Ref1, _} = mdns_registry:register_service(
        "Svc One", "_ipp._tcp", 80, [], service_local_target(5), #{probe => false}
    ),
    {ok, Ref2, _} = mdns_registry:register_service(
        "Svc Two", "_ipp._tcp", 81, [], service_local_target(6), #{probe => false}
    ),
    ?assertMatch(
        [{~"_ipp._tcp.local", _}],
        mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)
    ),
    ok = mdns_registry:unregister(Ref1),
    %% Svc Two is still live - the shared meta-PTR must not be withdrawn yet.
    ?assertMatch(
        [{~"_ipp._tcp.local", _}],
        mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)
    ),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)).

target_host_need_not_be_separately_registered() ->
    %% "otherhost.local" is never registered via mdns_registry:register/2,3
    %% - the SRV target can be an arbitrary .local name.
    {ok, Ref, FinalName} = mdns_registry:register_service(
        "Proxy Svc", "_http._tcp", 80, [], "otherhost.local", #{probe => false}
    ),
    ?assertMatch(
        [{{0, 0, 80, ~"otherhost.local"}, _}], mdns_registry:answers_for(FinalName, srv)
    ),
    ok = mdns_registry:unregister(Ref).

rejects_bad_service_type() ->
    ?assertMatch(
        {error, {invalid_service_type, _}},
        mdns_registry:register_service(
            "X", "not-a-service-type", 80, [], service_local_target(7)
        )
    ),
    ?assertMatch(
        {error, {invalid_service_type, _}},
        mdns_registry:register_service("X", "_http._sctp", 80, [], service_local_target(7))
    ).

rejects_bad_port() ->
    ?assertMatch(
        {error, {invalid_port, _}},
        mdns_registry:register_service("X", "_http._tcp", -1, [], service_local_target(8))
    ),
    ?assertMatch(
        {error, {invalid_port, _}},
        mdns_registry:register_service("X", "_http._tcp", 70000, [], service_local_target(8))
    ).

rejects_non_local_target_host() ->
    ?assertMatch(
        {error, {not_local, _}},
        mdns_registry:register_service("X", "_http._tcp", 80, [], "example.com")
    ).

rejects_validate_option_for_services() ->
    %% `validate` is a register/2,3-only option (there's no address to
    %% sanity-check for a service) - unlike register/2,3, this must be
    %% rejected rather than silently ignored.
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register_service(
            "X", "_http._tcp", 80, [], service_local_target(9), #{validate => false}
        )
    ).

start() ->
    {ok, Pid} = mdns_registry:start_link(),
    Pid.

stop(Pid) ->
    gen_server:stop(Pid).

%% A sibling address in the same subnet as whatever interface got
%% auto-detected - portable across whatever machine/CI runner this runs
%% on, since it derives from the same interface mdns_registry itself uses.
sibling_ip(Offset) ->
    {ok, {{A, B, C, D}, _Netmask}} = mdns_iface:resolve_with_netmask(undefined),
    {A, B, C, (D + Offset) rem 256}.

register_and_unregister() ->
    Ip = sibling_ip(1),
    {ok, Ref, ~"test-reg.local"} = mdns_registry:register("test-reg.local", Ip, #{
        probe => false
    }),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for(~"test-reg.local", a)),
    ok = mdns_registry:unregister(Ref),
    ?assertEqual([], mdns_registry:answers_for(~"test-reg.local", a)),
    %% unregistering an already-gone ref is a no-op, not an error
    ok = mdns_registry:unregister(Ref).

auto_withdraw_on_process_death() ->
    Ip = sibling_ip(2),
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, _Ref, _} = mdns_registry:register("test-death.local", Ip, #{probe => false}),
        Parent ! registered,
        receive
            stop -> ok
        end
    end),
    receive
        registered -> ok
    after 1000 -> ?assert(false)
    end,
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for(~"test-death.local", a)),
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Mon, process, Pid, killed} -> ok
    after 1000 -> ?assert(false)
    end,
    %% mdns_registry has its own, independent monitor on Pid - give it a
    %% moment to process its own 'DOWN' before asserting cleanup happened.
    timer:sleep(50),
    ?assertEqual([], mdns_registry:answers_for(~"test-death.local", a)).

takeover_keeps_registration_alive() ->
    Ip = sibling_ip(3),
    Parent = self(),
    Pid1 = spawn(fun() ->
        {ok, _Ref, _} = mdns_registry:register("test-takeover.local", Ip, #{probe => false}),
        Parent ! ready,
        receive
            stop -> ok
        end
    end),
    receive
        ready -> ok
    after 1000 -> ?assert(false)
    end,
    {ok, Ref2, _} = mdns_registry:register("test-takeover.local", Ip, #{probe => false}),
    Mon1 = monitor(process, Pid1),
    exit(Pid1, kill),
    receive
        {'DOWN', Mon1, process, Pid1, killed} -> ok
    after 1000 -> ?assert(false)
    end,
    timer:sleep(50),
    %% Pid1's death must not withdraw the registration Ref2 took over.
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for(~"test-takeover.local", a)),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for(~"test-takeover.local", a)).

rejects_out_of_subnet_address_by_default() ->
    %% RFC 5737 TEST-NET-3: guaranteed not to be this host's subnet. Fails
    %% at the precheck stage, before probing, so no real socket needed.
    ?assertMatch(
        {error, {address_not_on_subnet, _}},
        mdns_registry:register("test-subnet.local", {203, 0, 113, 1})
    ).

validate_false_allows_out_of_subnet_address() ->
    {ok, Ref, _} = mdns_registry:register("test-subnet-override.local", {203, 0, 113, 1}, #{
        validate => false, probe => false
    }),
    ?assertMatch(
        [{{203, 0, 113, 1}, _}], mdns_registry:answers_for(~"test-subnet-override.local", a)
    ),
    ok = mdns_registry:unregister(Ref).

rejects_non_local_name() ->
    ?assertMatch(
        {error, {not_local, _}},
        mdns_registry:register("example.com", sibling_ip(4))
    ).

rejects_invalid_address_shape() ->
    ?assertMatch(
        {error, {invalid_address, _}},
        mdns_registry:register("test-bad-addr.local", not_an_ip)
    ).

rejects_out_of_range_address() ->
    %% Shape looks right (a 4-tuple of integers) but octets are out of
    %% range - must be rejected, not silently truncated onto the wire.
    ?assertMatch(
        {error, {invalid_address, _}},
        mdns_registry:register("test-bad-range.local", {999, -5, 300, 1}, #{validate => false})
    ).

%% A crashing gen_server here would destroy mdns_registry_tab and drop
%% every other caller's live registrations too - these must fail cleanly.
rejects_non_boolean_validate_option_without_crashing() ->
    Pid = whereis(mdns_registry),
    Ip = sibling_ip(5),
    {ok, Ref, _} = mdns_registry:register("test-survivor.local", Ip, #{probe => false}),
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-opts.local", sibling_ip(6), #{validate => not_a_boolean})
    ),
    ?assertEqual(Pid, whereis(mdns_registry)),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for(~"test-survivor.local", a)),
    ok = mdns_registry:unregister(Ref).

rejects_non_boolean_probe_option() ->
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-probe-opt.local", sibling_ip(9), #{probe => not_a_boolean})
    ).

rejects_invalid_on_conflict_option() ->
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-conflict-opt.local", sibling_ip(10), #{
            probe => false, on_conflict => 'maybe'
        })
    ),
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-conflict-opt2.local", sibling_ip(11), #{
            probe => false, on_conflict => {rename, fun(_) -> ok end}
        })
    ).

%% No conflict occurs here (probe => false), so this only exercises opts
%% validation accepting `auto` - see mdns_registry_probe_tests for `auto`
%% actually resolving a conflict.
accepts_auto_on_conflict_option() ->
    {ok, Ref, _} = mdns_registry:register("test-auto-opt.local", sibling_ip(31), #{
        probe => false, on_conflict => auto
    }),
    ok = mdns_registry:unregister(Ref).

rejects_unknown_option_without_crashing() ->
    Pid = whereis(mdns_registry),
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-opts2.local", sibling_ip(7), #{typo_opt => true})
    ),
    ?assertEqual(Pid, whereis(mdns_registry)).

refresh_interface_leaves_registry_usable() ->
    ?assertEqual(ok, mdns_registry:refresh_interface()),
    Ip = sibling_ip(8),
    {ok, Ref, _} = mdns_registry:register("test-after-refresh.local", Ip, #{probe => false}),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for(~"test-after-refresh.local", a)),
    ok = mdns_registry:unregister(Ref).

%% -- RFC 6762 section 9: ongoing conflict defense --------------------------
%% mdns_registry:notify_conflict/3 is mdns_socket's real entry point for
%% this; calling it directly here exercises the same state machine
%% without needing a real socket or wire traffic.

%% notify_conflict/3 is a cast - call this after each one so the test
%% doesn't race ahead of mdns_registry actually processing it (a
%% subsequent gen_server:call can only reply after every previously
%% enqueued cast has already been handled, since a gen_server processes
%% its mailbox in arrival order).
sync() ->
    ok = mdns_registry:refresh_interface().

ongoing_conflict_is_defended_once_then_given_up() ->
    Ip = sibling_ip(12),
    Other = sibling_ip(13),
    {ok, Ref, _} = mdns_registry:register("test-defend.local", Ip, #{probe => false}),
    %% First conflicting answer: defended, still registered.
    ok = mdns_registry:notify_conflict(~"test-defend.local", a, Other),
    sync(),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(~"test-defend.local", a)),
    %% Same conflict again, right away (within the grace window): give up.
    ok = mdns_registry:notify_conflict(~"test-defend.local", a, Other),
    sync(),
    ?assertEqual([], mdns_registry:answers_for(~"test-defend.local", a)),
    receive
        {mdns_bridge_conflict, Ref, ~"test-defend.local"} -> ok
    after 1000 -> ?assert(false)
    end.

ongoing_conflict_is_ignored_for_our_own_sibling_data() ->
    Ip1 = sibling_ip(14),
    Ip2 = sibling_ip(15),
    {ok, Ref1, _} = mdns_registry:register("test-roundrobin.local", Ip1, #{probe => false}),
    {ok, Ref2, _} = mdns_registry:register("test-roundrobin.local", Ip2, #{probe => false}),
    %% "Conflict" report matching one of our own sibling registrations
    %% must not trigger defense/give-up at all.
    ok = mdns_registry:notify_conflict(~"test-roundrobin.local", a, Ip2),
    sync(),
    ?assertEqual(2, length(mdns_registry:answers_for(~"test-roundrobin.local", a))),
    ok = mdns_registry:unregister(Ref1),
    ok = mdns_registry:unregister(Ref2).

force_on_conflict_never_gives_up_ongoing_defense() ->
    Ip = sibling_ip(16),
    Other = sibling_ip(17),
    {ok, _Ref, _} = mdns_registry:register("test-force-defend.local", Ip, #{
        probe => false, on_conflict => force
    }),
    ok = mdns_registry:notify_conflict(~"test-force-defend.local", a, Other),
    sync(),
    ok = mdns_registry:notify_conflict(~"test-force-defend.local", a, Other),
    sync(),
    ok = mdns_registry:notify_conflict(~"test-force-defend.local", a, Other),
    sync(),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for(~"test-force-defend.local", a)).
