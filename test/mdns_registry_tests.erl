-module(mdns_registry_tests).

-include_lib("eunit/include/eunit.hrl").

%% mdns_registry announces via mdns_socket:announce/3 (a gen_server cast,
%% which never fails even if the target isn't running), so these tests
%% don't need a real mdns_socket/UDP socket - just the registry itself.

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
            fun rejects_unknown_option_without_crashing/0,
            fun refresh_interface_leaves_registry_usable/0
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
    {ok, Ref} = mdns_registry:register("test-reg.local", Ip),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-reg.local", a)),
    ok = mdns_registry:unregister(Ref),
    ?assertEqual([], mdns_registry:answers_for("test-reg.local", a)),
    %% unregistering an already-gone ref is a no-op, not an error
    ok = mdns_registry:unregister(Ref).

auto_withdraw_on_process_death() ->
    Ip = sibling_ip(2),
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, _Ref} = mdns_registry:register("test-death.local", Ip),
        Parent ! registered,
        receive
            stop -> ok
        end
    end),
    receive
        registered -> ok
    after 1000 -> ?assert(timeout_waiting_for_registration)
    end,
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-death.local", a)),
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', Mon, process, Pid, killed} -> ok
    after 1000 -> ?assert(timeout_waiting_for_down)
    end,
    %% mdns_registry has its own, independent monitor on Pid - give it a
    %% moment to process its own 'DOWN' before asserting cleanup happened.
    timer:sleep(50),
    ?assertEqual([], mdns_registry:answers_for("test-death.local", a)).

takeover_keeps_registration_alive() ->
    Ip = sibling_ip(3),
    Parent = self(),
    Pid1 = spawn(fun() ->
        {ok, _Ref} = mdns_registry:register("test-takeover.local", Ip),
        Parent ! ready,
        receive
            stop -> ok
        end
    end),
    receive
        ready -> ok
    after 1000 -> ?assert(timeout_waiting_for_registration)
    end,
    {ok, Ref2} = mdns_registry:register("test-takeover.local", Ip),
    Mon1 = monitor(process, Pid1),
    exit(Pid1, kill),
    receive
        {'DOWN', Mon1, process, Pid1, killed} -> ok
    after 1000 -> ?assert(timeout_waiting_for_down)
    end,
    timer:sleep(50),
    %% Pid1's death must not withdraw the registration Ref2 took over.
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-takeover.local", a)),
    ok = mdns_registry:unregister(Ref2),
    ?assertEqual([], mdns_registry:answers_for("test-takeover.local", a)).

rejects_out_of_subnet_address_by_default() ->
    %% RFC 5737 TEST-NET-3: guaranteed not to be this host's subnet.
    ?assertMatch(
        {error, {address_not_on_subnet, _}},
        mdns_registry:register("test-subnet.local", {203, 0, 113, 1})
    ).

validate_false_allows_out_of_subnet_address() ->
    {ok, Ref} = mdns_registry:register("test-subnet-override.local", {203, 0, 113, 1}, #{
        validate => false
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
    {ok, Ref} = mdns_registry:register("test-survivor.local", Ip),
    ?assertMatch(
        {error, {invalid_opts, _}},
        mdns_registry:register("test-bad-opts.local", sibling_ip(6), #{validate => not_a_boolean})
    ),
    ?assertEqual(Pid, whereis(mdns_registry)),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-survivor.local", a)),
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
    {ok, Ref} = mdns_registry:register("test-after-refresh.local", Ip),
    ?assertMatch([{Ip, _Ttl}], mdns_registry:answers_for("test-after-refresh.local", a)),
    ok = mdns_registry:unregister(Ref).
