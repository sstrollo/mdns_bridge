-module(mdns_trace_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_trace.hrl").

trace_test_() ->
    {foreach, fun start/0, fun stop/1, [
        fun disabled_by_default_produces_no_output/0,
        fun enabled_prints_every_event_to_the_given_device/0,
        fun disable_stops_further_output/0,
        fun enable_again_with_a_different_device_moves_the_output/0,
        fun enabled_reports_current_state/0,
        fun trace_macro_does_not_construct_info_when_disabled/0
    ]}.

start() ->
    ok.

stop(_) ->
    mdns_trace:disable().

%% A unique temp file per test, read back and deleted - same technique
%% as mdns_cache_tests' print/1 coverage.
temp_path() ->
    "mdns_trace_test_" ++ integer_to_list(erlang:unique_integer([positive])).

read_and_delete(Path) ->
    {ok, Bin} = file:read_file(Path),
    ok = file:delete(Path),
    binary_to_list(Bin).

disabled_by_default_produces_no_output() ->
    ?assertEqual(ok, mdns_trace:event(some_kind, #{a => 1})),
    %% No assertion beyond "didn't crash and didn't print anywhere
    %% observable" - there's nothing listening by default.
    ok.

enabled_prints_every_event_to_the_given_device() ->
    Path = temp_path(),
    {ok, F} = file:open(Path, [write]),
    ok = mdns_trace:enable(F),
    timer:sleep(20),
    ok = mdns_trace:event(added, #{name => ~"foo.local", ttl => 120}),
    timer:sleep(20),
    ok = file:close(F),
    Text = read_and_delete(Path),
    ?assert(string:find(Text, "added") =/= nomatch),
    ?assert(string:find(Text, "foo.local") =/= nomatch).

disable_stops_further_output() ->
    Path = temp_path(),
    {ok, F} = file:open(Path, [write]),
    ok = mdns_trace:enable(F),
    timer:sleep(20),
    ok = mdns_trace:event(before_disable, #{}),
    timer:sleep(20),
    ok = mdns_trace:disable(),
    ok = mdns_trace:event(after_disable, #{}),
    timer:sleep(20),
    ok = file:close(F),
    Text = read_and_delete(Path),
    ?assert(string:find(Text, "before_disable") =/= nomatch),
    ?assertEqual(nomatch, string:find(Text, "after_disable")).

enabled_reports_current_state() ->
    ?assertNot(mdns_trace:enabled()),
    ok = mdns_trace:enable(),
    ?assert(mdns_trace:enabled()),
    ok = mdns_trace:disable(),
    ?assertNot(mdns_trace:enabled()).

%% The whole point of ?TRACE/2: Info must not even be *evaluated* while
%% disabled, not merely have its result discarded - proven here with a
%% side-effecting Info expression (sends a message to self()), not just
%% by checking there's no printed output.
trace_macro_does_not_construct_info_when_disabled() ->
    Self = self(),
    SideEffectingInfo = fun() ->
        Self ! info_was_constructed,
        #{}
    end,
    ?TRACE(some_kind, SideEffectingInfo()),
    ?assertEqual(
        no_message,
        receive
            info_was_constructed -> got_message
        after 0 -> no_message
        end
    ),
    ok = mdns_trace:enable(),
    timer:sleep(20),
    ?TRACE(some_kind, SideEffectingInfo()),
    ?assertEqual(
        got_message,
        receive
            info_was_constructed -> got_message
        after 1000 -> no_message
        end
    ).

enable_again_with_a_different_device_moves_the_output() ->
    Path1 = temp_path(),
    Path2 = temp_path(),
    {ok, F1} = file:open(Path1, [write]),
    {ok, F2} = file:open(Path2, [write]),
    ok = mdns_trace:enable(F1),
    timer:sleep(20),
    ok = mdns_trace:event(to_first, #{}),
    timer:sleep(20),
    %% Re-enabling (even without an explicit disable first) must fully
    %% switch over - no events should keep going to the old device.
    ok = mdns_trace:enable(F2),
    timer:sleep(20),
    ok = mdns_trace:event(to_second, #{}),
    timer:sleep(20),
    ok = file:close(F1),
    ok = file:close(F2),
    Text1 = read_and_delete(Path1),
    Text2 = read_and_delete(Path2),
    ?assert(string:find(Text1, "to_first") =/= nomatch),
    ?assertEqual(nomatch, string:find(Text1, "to_second")),
    ?assert(string:find(Text2, "to_second") =/= nomatch),
    ?assertEqual(nomatch, string:find(Text2, "to_first")).
