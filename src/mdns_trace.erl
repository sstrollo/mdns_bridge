%%%-------------------------------------------------------------------
%% @doc Toggleable tracing for high-frequency internal events (cache
%% inserts/removals, and anywhere else that later calls event/2) that
%% are too noisy to leave on at `debug' log level permanently, but are
%% still worth being able to watch on demand.
%%
%% Built on Erlang's own call-tracing (`erlang:trace/3' +
%% `erlang:trace_pattern/3'), not a log-level check: event/2's body does
%% nothing at all - whether a call to it produces any output is decided
%% entirely by the BEAM's own trace machinery, at the VM level, not by a
%% branch in this module. That means disabled tracing costs exactly one
%% do-nothing function call at each instrumented site (the same call
%% that would otherwise have gone to `logger:debug/2', but without
%% logger's own formatting/filtering machinery running first) - and
%% enabling it doesn't need touching call sites, a config value, or an
%% extra OTP application (deliberately not using `dbg', which lives in
%% `runtime_tools' - not something an embedding release is guaranteed to
%% include): `erlang:trace/3' and `erlang:trace_pattern/3' are plain
%% BIFs.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_trace).

-export([enable/0, enable/1, disable/0, event/2]).

-define(SERVER, ?MODULE).

%% Call at each point that should be observable when tracing is
%% enabled - Kind identifies the kind of event (an atom), Info carries
%% whatever's relevant to it (a map, by convention, for legible trace
%% output - see mdns_cache for examples). Does nothing on its own; see
%% the moduledoc.
-spec event(atom(), term()) -> ok.
event(_Kind, _Info) ->
    ok.

%% Equivalent to enable(standard_io).
-spec enable() -> ok.
enable() ->
    enable(standard_io).

%% Start tracing every call to event/2, from any process, printing each
%% one to IoDevice. Safe to call again (with the same or a different
%% IoDevice) while already enabled - always starts from a clean state.
-spec enable(io:device()) -> ok.
enable(IoDevice) ->
    disable(),
    TracerPid = spawn(fun() -> tracer_init(IoDevice) end),
    erlang:trace_pattern({?MODULE, event, 2}, true, []),
    erlang:trace(all, true, [call, {tracer, TracerPid}]),
    ok.

-spec disable() -> ok.
disable() ->
    erlang:trace(all, false, [call]),
    erlang:trace_pattern({?MODULE, event, 2}, false, []),
    case whereis(?SERVER) of
        undefined ->
            ok;
        Pid ->
            Pid ! stop,
            ok
    end.

tracer_init(IoDevice) ->
    register(?SERVER, self()),
    tracer_loop(IoDevice).

tracer_loop(IoDevice) ->
    receive
        {trace, Pid, call, {?MODULE, event, [Kind, Info]}} ->
            io:format(IoDevice, "mdns_trace: ~0p ~0p ~0p\n", [Pid, Kind, Info]),
            tracer_loop(IoDevice);
        stop ->
            ok
    end.
