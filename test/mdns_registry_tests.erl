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
            fun rejects_names_that_cannot_be_encoded/0,
            fun rejects_non_boolean_validate_option_without_crashing/0,
            fun rejects_non_boolean_probe_option/0,
            fun rejects_invalid_on_conflict_option/0,
            fun accepts_auto_on_conflict_option/0,
            fun rejects_unknown_option_without_crashing/0,
            fun refresh_interface_leaves_registry_usable/0,
            fun withdraw_all_withdraws_every_registration/0,
            fun ongoing_conflict_is_defended_once_then_given_up/0,
            fun ongoing_conflict_is_ignored_for_our_own_sibling_data/0,
            fun defense_state_is_dropped_with_the_last_registration/0,
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
            fun rejects_validate_option_for_services/0,
            fun rejects_service_names_and_txt_that_cannot_be_encoded/0,
            fun reregistering_an_instance_with_new_txt_replaces_the_old_txt/0,
            fun reregistering_an_identical_instance_does_not_leak_the_meta_ptr/0,
            fun takeover_of_the_last_instance_of_a_type_keeps_the_meta_ptr/0
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
    ),
    ?assertMatch(
        {error, {invalid_service_type, _}},
        mdns_registry:register_service("X", "_._tcp", 80, [], service_local_target(7))
    ),
    %% DNS names are case-insensitive: the type check must agree with
    %% service_type_name/1, which lowercases.
    {ok, Ref, Name} = mdns_registry:register_service(
        "X", ~"_HTTP._TCP", 80, [], service_local_target(7), #{probe => false}
    ),
    ?assertEqual(~"x._http._tcp.local", Name),
    ok = mdns_registry:unregister(Ref).

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

rejects_service_names_and_txt_that_cannot_be_encoded() ->
    Opts = #{probe => false},
    Target = service_local_target(23),
    ?assertMatch(
        {error, {invalid_name, _, label_too_long}},
        mdns_registry:register_service(
            lists:duplicate(64, $i), "_http._tcp", 80, [], Target, Opts
        )
    ),
    ?assertMatch(
        {error, {invalid_name, _, label_too_long}},
        mdns_registry:register_service(
            "Ok Label", "_http._tcp", 80, [], lists:duplicate(64, $t) ++ ".local", Opts
        )
    ),
    ?assertMatch(
        {error, {txt_string_too_long, _}},
        mdns_registry:register_service(
            "Ok Label", "_http._tcp", 80, [{"k", lists:duplicate(254, $v)}], Target, Opts
        )
    ),
    %% ...and the limit is 255 bytes per string, not 254: a 253-byte
    %% value plus "k=" is exactly 255.
    {ok, Ref, _} = mdns_registry:register_service(
        "Ok Label", "_http._tcp", 80, [{"k", lists:duplicate(253, $v)}], Target, Opts
    ),
    ok = mdns_registry:unregister(Ref).

%% Updating a service's TXT record by registering the same instance again
%% is the normal way to change it. The previous registration shares the
%% SRV and PTR keys (taken over) but not the TXT key - that old TXT row
%% must go with the rest of the old registration, not linger on as an
%% orphan nobody can unregister (and the old owner's meta-PTR count
%% must be released, or the meta-PTR would outlive every registration).
reregistering_an_instance_with_new_txt_replaces_the_old_txt() ->
    Opts = #{probe => false},
    Target = service_local_target(20),
    {ok, Ref1, Name} = mdns_registry:register_service(
        "Retxt", "_retxt._tcp", 80, [{"v", "1"}], Target, Opts
    ),
    {ok, Ref2, Name} = mdns_registry:register_service(
        "Retxt", "_retxt._tcp", 80, [{"v", "2"}], Target, Opts
    ),
    ?assertMatch([{[~"v=2"], _}], mdns_registry:answers_for(Name, txt)),
    ?assertMatch([{{0, 0, 80, _}, _}], mdns_registry:answers_for(Name, srv)),
    %% The taken-over registration's ref is gone: unregistering it is a
    %% no-op that must not disturb the new one.
    ok = mdns_registry:unregister(Ref1),
    ?assertMatch([{[~"v=2"], _}], mdns_registry:answers_for(Name, txt)),
    ?assertMatch([{_, _}], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for(Name, txt)),
    ?assertEqual([], mdns_registry:answers_for(Name, srv)),
    ?assertEqual([], mdns_registry:answers_for(~"_retxt._tcp.local", ptr)),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)).

reregistering_an_identical_instance_does_not_leak_the_meta_ptr() ->
    Opts = #{probe => false},
    Target = service_local_target(21),
    {ok, Ref1, Name} = mdns_registry:register_service("Same", "_same._tcp", 80, [], Target, Opts),
    {ok, Ref2, Name} = mdns_registry:register_service("Same", "_same._tcp", 80, [], Target, Opts),
    ok = mdns_registry:unregister(Ref1),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)),
    ?assertEqual(#{}, meta_ptr_refs_in_state()).

%% The takeover must not dip the type's count to zero in between (which
%% would goodbye the meta-PTR and immediately re-announce it).
takeover_of_the_last_instance_of_a_type_keeps_the_meta_ptr() ->
    Opts = #{probe => false},
    Target = service_local_target(22),
    {ok, _Ref1, Name} = mdns_registry:register_service("Only", "_only._tcp", 80, [], Target, Opts),
    {ok, Ref2, Name} = mdns_registry:register_service("Only", "_only._tcp", 81, [], Target, Opts),
    ?assertEqual(#{~"_only._tcp.local" => 1}, meta_ptr_refs_in_state()),
    ?assertMatch([{{0, 0, 81, _}, _}], mdns_registry:answers_for(Name, srv)),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual(#{}, meta_ptr_refs_in_state()).

%% #state.meta_ptr_refs, read positionally - sys:get_state/1 is the
%% standard debug/testing escape hatch (same technique as mdns_cache_tests).
meta_ptr_refs_in_state() ->
    element(6, sys:get_state(mdns_registry)).

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

%% inet_dns:encode/2 raises on a label over 63 bytes, an empty label, or
%% a name over 255 wire bytes - and it would do so inside mdns_socket,
%% on every announcement, for as long as the name stayed registered.
%% Such names are refused up front instead.
rejects_names_that_cannot_be_encoded() ->
    Ip = sibling_ip(32),
    Opts = #{probe => false},
    ?assertMatch(
        {error, {invalid_name, _, label_too_long}},
        mdns_registry:register(lists:duplicate(64, $a) ++ ".local", Ip, Opts)
    ),
    ?assertMatch(
        {error, {invalid_name, _, empty_label}},
        mdns_registry:register("double..dot.local", Ip, Opts)
    ),
    ?assertMatch(
        {error, {invalid_name, _, name_too_long}},
        mdns_registry:register(
            lists:flatten(lists:join(".", lists:duplicate(5, lists:duplicate(60, $x)))) ++
                ".local",
            Ip,
            Opts
        )
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

%% What mdns_app:prep_stop/1 relies on: hosts and services alike, from
%% any owner, all gone in one call - and the refs harmlessly stale.
withdraw_all_withdraws_every_registration() ->
    Opts = #{probe => false},
    {ok, Ref1, _} = mdns_registry:register("withdraw-all-1.local", sibling_ip(33), Opts),
    {ok, Ref2, _} = mdns_registry:register("withdraw-all-2.local", sibling_ip(34), Opts),
    {ok, Ref3, SvcName} = mdns_registry:register_service(
        "Withdraw All", "_wall._tcp", 80, [], service_local_target(30), Opts
    ),
    ok = mdns_registry:withdraw_all(),
    ?assertEqual([], mdns_registry:answers_for(~"withdraw-all-1.local", a)),
    ?assertEqual([], mdns_registry:answers_for(~"withdraw-all-2.local", a)),
    ?assertEqual([], mdns_registry:answers_for(SvcName, srv)),
    ?assertEqual([], mdns_registry:answers_for(~"_wall._tcp.local", ptr)),
    ?assertEqual([], mdns_registry:answers_for(~"_services._dns-sd._udp.local", ptr)),
    ?assertEqual(#{}, meta_ptr_refs_in_state()),
    [ok = mdns_registry:unregister(Ref) || Ref <- [Ref1, Ref2, Ref3]],
    %% ...and the registry is still usable afterwards.
    {ok, Ref4, _} = mdns_registry:register("withdraw-all-after.local", sibling_ip(35), Opts),
    ok = mdns_registry:unregister(Ref4).

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

%% A defense timestamp only means something while the name is held; it
%% must not accumulate in state for every name ever defended and then
%% unregistered - but must survive while a sibling still holds the name.
defense_state_is_dropped_with_the_last_registration() ->
    Ip1 = sibling_ip(36),
    Ip2 = sibling_ip(37),
    Other = sibling_ip(38),
    {ok, Ref1, _} = mdns_registry:register("test-defense-prune.local", Ip1, #{probe => false}),
    {ok, Ref2, _} = mdns_registry:register("test-defense-prune.local", Ip2, #{probe => false}),
    ok = mdns_registry:notify_conflict(~"test-defense-prune.local", a, Other),
    sync(),
    ?assert(maps:is_key({~"test-defense-prune.local", a}, defenses_in_state())),
    ok = mdns_registry:unregister(Ref1),
    ?assert(maps:is_key({~"test-defense-prune.local", a}, defenses_in_state())),
    ok = mdns_registry:unregister(Ref2),
    ?assertNot(maps:is_key({~"test-defense-prune.local", a}, defenses_in_state())).

defenses_in_state() ->
    element(5, sys:get_state(mdns_registry)).

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
