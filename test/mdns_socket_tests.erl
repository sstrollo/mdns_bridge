-module(mdns_socket_tests).

-include_lib("eunit/include/eunit.hrl").

socket_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [fun refresh_interface_is_a_noop_when_unchanged/0]
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
