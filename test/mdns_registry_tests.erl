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
    {ok, Ref, "test-reg.local"} = mdns_registry:register("test-reg.local", Ip, #{probe => false}),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-reg.local", a)),
    ok = mdns_registry:unregister(Ref),
    ?assertEqual([], mdns_registry:answers_for("test-reg.local", a)),
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
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-death.local", a)),
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Mon, process, Pid, killed} -> ok
    after 1000 -> ?assert(false)
    end,
    %% mdns_registry has its own, independent monitor on Pid - give it a
    %% moment to process its own 'DOWN' before asserting cleanup happened.
    timer:sleep(50),
    ?assertEqual([], mdns_registry:answers_for("test-death.local", a)).

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
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-takeover.local", a)),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for("test-takeover.local", a)).

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
        [{{203, 0, 113, 1}, _}], mdns_registry:answers_for("test-subnet-override.local", a)
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
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-survivor.local", a)),
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
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-after-refresh.local", a)),
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
    ok = mdns_registry:notify_conflict("test-defend.local", a, Other),
    sync(),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for("test-defend.local", a)),
    %% Same conflict again, right away (within the grace window): give up.
    ok = mdns_registry:notify_conflict("test-defend.local", a, Other),
    sync(),
    ?assertEqual([], mdns_registry:answers_for("test-defend.local", a)),
    receive
        {mdns_bridge_conflict, Ref, "test-defend.local"} -> ok
    after 1000 -> ?assert(false)
    end.

ongoing_conflict_is_ignored_for_our_own_sibling_data() ->
    Ip1 = sibling_ip(14),
    Ip2 = sibling_ip(15),
    {ok, Ref1, _} = mdns_registry:register("test-roundrobin.local", Ip1, #{probe => false}),
    {ok, Ref2, _} = mdns_registry:register("test-roundrobin.local", Ip2, #{probe => false}),
    %% "Conflict" report matching one of our own sibling registrations
    %% must not trigger defense/give-up at all.
    ok = mdns_registry:notify_conflict("test-roundrobin.local", a, Ip2),
    sync(),
    ?assertEqual(2, length(mdns_registry:answers_for("test-roundrobin.local", a))),
    ok = mdns_registry:unregister(Ref1),
    ok = mdns_registry:unregister(Ref2).

force_on_conflict_never_gives_up_ongoing_defense() ->
    Ip = sibling_ip(16),
    Other = sibling_ip(17),
    {ok, _Ref, _} = mdns_registry:register("test-force-defend.local", Ip, #{
        probe => false, on_conflict => force
    }),
    ok = mdns_registry:notify_conflict("test-force-defend.local", a, Other),
    sync(),
    ok = mdns_registry:notify_conflict("test-force-defend.local", a, Other),
    sync(),
    ok = mdns_registry:notify_conflict("test-force-defend.local", a, Other),
    sync(),
    ?assertMatch([{Ip, _}], mdns_registry:answers_for("test-force-defend.local", a)).
