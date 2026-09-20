-module(mdns_socket_tests).

-include_lib("eunit/include/eunit.hrl").

socket_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun refresh_interface_is_a_noop_when_unchanged/0,
            fun probe_subscribe_and_unsubscribe_update_state/0,
            fun a_dead_probe_watcher_does_not_leak/0
        ]
    end}.

start() ->
    {ok, Pid} = mdns_socket:start_link(),
    Pid.

stop(Pid) ->
    gen_server:stop(Pid).

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

%% #state.probe_watchers, read positionally since the record isn't
%% shared via a header - sys:get_state/1 is a standard debug/testing
%% escape hatch (same technique used in mdns_cache_tests).
probe_watchers_in_state() ->
    element(4, sys:get_state(mdns_socket)).
