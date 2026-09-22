%%%-------------------------------------------------------------------
%% @doc In-memory cache of records learned from mDNS traffic.
%%
%% Storage is a public ETS table keyed by {Name, Type, Data} so reads
%% (lookup/2, near_expiry/1) never have to go through the gen_server -
%% only inserts and the expiry sweep are serialized through this process.
%%
%% Implements RFC 6762 10.2 cache-flush semantics: an inserted record
%% with the cache-flush bit set replaces other records for the same
%% {Name, Type} that are more than ?FLUSH_GRACE_MS old (a short grace
%% window, so a single flush that spans more than one packet - e.g.
%% several round-robin A records announced together - doesn't have its
%% own records race-delete each other). Without this, conflicting
%% records for the same name accumulate forever and anyone on the
%% network can add a competing answer alongside a legitimate one.
%%
%% Also enforces a configurable cache_max_entries: once over the cap,
%% the oldest entries (by insertion time) are evicted to make room,
%% bounding memory use against a noisy or adversarial network.
%%
%% Callers that want to be woken up when a not-yet-cached name appears
%% (mdns_query's on-demand resolve) call await/3, a plain blocking
%% gen_server:call: if nothing matches yet, this process registers the
%% caller as a waiter (monitoring it, and setting a timer for TimeoutMs)
%% and replies later, from insert_many/1's handling, via
%% gen_server:reply/2 - no ETS, no raw `receive` in the caller.
%%
%% Every insert/removal/eviction is instrumented via ?TRACE/2
%% - too frequent to leave on at `debug' log level permanently on a busy
%% network, but toggleable on demand with mdns_trace:enable/0,1.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_cache).

-behaviour(gen_server).

-include("mdns_trace.hrl").

-export([
    child_spec/0,
    start_link/0,
    insert_many/1,
    lookup/2,
    near_expiry/1,
    await/3,
    dump/0,
    print/0,
    print/1
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(TAB, mdns_cache_tab).
-define(SWEEP_INTERVAL_MS, 5000).
-define(FLUSH_GRACE_MS, 1000).
-define(DEFAULT_MAX_ENTRIES, 10000).

%% Keyed by the monitor ref watching that waiter's caller - doubles as
%% the timer's identity, so both the 'DOWN' and the timeout message that
%% can end a wait carry the exact key needed to find and remove it.
-type waiter() :: #{
    name := binary(),
    type := atom(),
    from := gen_server:from(),
    timer := reference() | undefined
}.

-record(state, {waiters = #{} :: #{reference() => waiter()}}).

%% Entry as produced by mdns_proto:extract_answers/1.
-type entry() :: {
    Name :: binary(),
    Type :: atom(),
    Data :: term(),
    Ttl :: non_neg_integer(),
    CacheFlush :: boolean()
}.

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Synchronous: callers (mdns_socket, mostly) rely on the insert having
%% landed - and any matching await/3 waiter replied to - before this
%% returns.
-spec insert_many([entry()]) -> ok.
insert_many(Entries) ->
    gen_server:call(?SERVER, {insert_many, Entries}).

%% Direct ETS read: current, unexpired {Data, RemainingTtlSeconds} answers.
-spec lookup(binary(), atom()) -> [{term(), non_neg_integer()}].
lookup(Name, Type) ->
    Now = now_ms(),
    [
        {Data, remaining_seconds(ExpiresAt, Now)}
     || [Data, ExpiresAt] <- ets:match(?TAB, {{Name, Type, '$1'}, {'$2', '_'}}),
        ExpiresAt > Now
    ].

%% {Name, Type} pairs with at least one unexpired entry due to expire
%% within WithinSeconds - candidates for proactive refresh.
-spec near_expiry(non_neg_integer()) -> [{binary(), atom()}].
near_expiry(WithinSeconds) ->
    Now = now_ms(),
    Horizon = Now + WithinSeconds * 1000,
    Keys = [
        {Name, Type}
     || [Name, Type, ExpiresAt] <- ets:match(?TAB, {{'$1', '$2', '_'}, {'$3', '_'}}),
        ExpiresAt > Now,
        ExpiresAt =< Horizon
    ],
    lists:usort(Keys).

%% Block until Name/Type has an answer - actively re-checked as new
%% entries are inserted, not polled - or return {error, timeout} after
%% TimeoutMs (or never, for `infinity`) if nothing shows up. A plain
%% gen_server:call: if there's no answer yet, this process (not the
%% caller) tracks the wait via a monitor on the caller and a timer, and
%% replies later with gen_server:reply/2 once one of the three things
%% that can end it happens - a matching insert, the timer, or the caller
%% dying - so nothing needs an explicit unsubscribe.
-spec await(binary(), atom(), timeout()) ->
    {ok, [{term(), non_neg_integer()}]} | {error, timeout}.
await(Name, Type, TimeoutMs) ->
    gen_server:call(?SERVER, {await, Name, Type, TimeoutMs}, infinity).

%% Direct ETS read: every current, unexpired entry - for inspecting the
%% cache from a shell (`rebar3 shell`) or a debug script. See print/0 for
%% a version that just formats this to stdout.
-spec dump() ->
    [
        #{
            name := binary(),
            type := atom(),
            data := term(),
            ttl_remaining := non_neg_integer(),
            age := non_neg_integer()
        }
    ].
dump() ->
    Now = now_ms(),
    [
        #{
            name => Name,
            type => Type,
            data => Data,
            ttl_remaining => remaining_seconds(ExpiresAt, Now),
            age => (Now - InsertedAt) div 1000
        }
     || {{Name, Type, Data}, {ExpiresAt, InsertedAt}} <- ets:tab2list(?TAB),
        ExpiresAt > Now
    ].

%% Equivalent to print(standard_io).
-spec print() -> ok.
print() ->
    print(standard_io).

%% Prints dump/0's result to IoDevice, one entry per line (a multi-entry
%% TXT record is the one exception - see format_data/2), sorted by
%% {Name, Type} for readability, and formatted for a human rather than
%% an `~p` dump of whatever Erlang term each record type happens to use
%% internally: an a/aaaa address via inet:ntoa/1, not a raw tuple; PTR's
%% target and each TXT string via ~s, not `~p`'s <<"...">> quoting; a
%% SRV's fields labeled. Anything this app doesn't specifically
%% understand (a raw binary for a record type we only ever pass through)
%% falls back to ~0p.
%%
%% Deliberately no fixed-width columns: io_lib's ~s/~w *truncate* (to a
%% row of `*`s, for ~w) a value wider than its given field width rather
%% than just leaving it unaligned - real names on a real network (a
%% reverse-DNS PTR query, a DNS-SD instance name) regularly are, and
%% silently losing part of a name defeats the entire point of a
%% debugging tool. Ragged columns beat truncated data.
-spec print(io:device()) -> ok.
print(IoDevice) ->
    Entries = lists:sort(
        fun(#{name := N1, type := T1}, #{name := N2, type := T2}) ->
            {N1, T1} =< {N2, T2}
        end,
        dump()
    ),
    [print_entry(IoDevice, Entry) || Entry <- Entries],
    io:format(IoDevice, "~b entries\n", [length(Entries)]).

print_entry(IoDevice, #{name := Name, type := Type, data := Data, ttl_remaining := Ttl, age := Age}) ->
    Header = io_lib:format("~s ~0p ttl=~b age=~b", [Name, Type, Ttl, Age]),
    case format_data(Type, Data) of
        {inline, Formatted} ->
            io:format(IoDevice, "~s ~s\n", [Header, Formatted]);
        {multiline, DataEntries} ->
            io:format(IoDevice, "~s\n", [Header]),
            [io:format(IoDevice, "  ~s\n", [DataEntry]) || DataEntry <- DataEntries]
    end.

%% a/aaaa: a dotted-quad or colon-hex address string, not a raw tuple -
%% falls back to ~0p for anything inet:ntoa/1 itself doesn't recognize
%% as a valid address rather than crashing print/1 over it.
format_data(Type, Data) when Type =:= a; Type =:= aaaa ->
    case inet:ntoa(Data) of
        {error, _} -> {inline, io_lib:format("~0p", [Data])};
        Address -> {inline, Address}
    end;
%% ptr: just the target name, unquoted.
format_data(ptr, Data) when is_binary(Data) ->
    {inline, Data};
%% srv: labeled fields, target unquoted - the priority/weight/port order
%% on the wire isn't obvious to read without labels the way an a/ptr
%% record's single value is.
format_data(srv, {Priority, Weight, Port, Target}) ->
    {inline,
        io_lib:format("priority=~b weight=~b port=~b target=~s", [
            Priority, Weight, Port, Target
        ])};
%% txt: unquoted, and - since a real TXT record can hold a couple dozen
%% strings (e.g. a printer's IPP capabilities) - one per (indented) line
%% once there's more than a single entry to keep scannable, rather than
%% cramming them all onto the entry's own line.
format_data(txt, []) ->
    {inline, <<>>};
format_data(txt, [Entry]) when is_binary(Entry) ->
    {inline, Entry};
format_data(txt, Data) when is_list(Data) ->
    {multiline, Data};
format_data(_Type, Data) ->
    {inline, io_lib:format("~0p", [Data])}.

init([]) ->
    ets:new(?TAB, [set, public, named_table, {read_concurrency, true}]),
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {ok, #state{}}.

handle_call({insert_many, Entries}, _From, State) ->
    Now = now_ms(),
    FlushKeys = lists:usort([{Name, Type} || {Name, Type, _Data, _Ttl, true} <- Entries]),
    [flush_stale(Key, Now) || Key <- FlushKeys],
    Touched = lists:usort([store_entry(E, Now) || E <- Entries]),
    NewState = lists:foldl(fun notify_waiters/2, State, Touched),
    enforce_max_entries(),
    {reply, ok, NewState};
handle_call({await, Name, Type, TimeoutMs}, {FromPid, _Tag} = From, State) ->
    case lookup(Name, Type) of
        [] ->
            Ref = erlang:monitor(process, FromPid),
            Timer = schedule_await_timeout(TimeoutMs, Ref),
            Waiter = #{name => Name, type => Type, from => From, timer => Timer},
            {noreply, State#state{waiters = (State#state.waiters)#{Ref => Waiter}}};
        Answers ->
            {reply, {ok, Answers}, State}
    end;
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(sweep, State) ->
    expire_rows(),
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {noreply, State};
handle_info({await_timeout, Ref}, State) ->
    case maps:take(Ref, State#state.waiters) of
        {#{from := From}, Waiters} ->
            erlang:demonitor(Ref, [flush]),
            gen_server:reply(From, {error, timeout}),
            {noreply, State#state{waiters = Waiters}};
        error ->
            %% Already answered by a matching insert (which cancels the
            %% timer, but the message can still be in transit) - ignore.
            {noreply, State}
    end;
handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    case maps:take(Ref, State#state.waiters) of
        {#{timer := Timer}, Waiters} ->
            cancel_timer(Timer),
            {noreply, State#state{waiters = Waiters}};
        error ->
            {noreply, State}
    end;
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- internal ---------------------------------------------------------

%% RFC 6762 10.2: a cache-flush record replaces other records for the
%% same {Name, Type} that are "known for more than one second" - delete
%% anything older than the grace window, leave the rest (this batch's
%% own entries, and anything from a flush burst spread across more than
%% one packet) alone.
flush_stale({Name, Type}, Now) ->
    Cutoff = Now - ?FLUSH_GRACE_MS,
    case
        ets:select_delete(?TAB, [
            {{{Name, Type, '_'}, {'_', '$1'}}, [{'<', '$1', Cutoff}], [true]}
        ])
    of
        0 ->
            ok;
        Count ->
            ?TRACE(cache_flush, #{count => Count, name => Name, type => Type})
    end.

store_entry({Name, Type, Data, 0, _CacheFlush}, _Now) ->
    %% mDNS goodbye packet: TTL=0 means "remove this record now".
    case ets:take(?TAB, {Name, Type, Data}) of
        [] ->
            ok;
        [_] ->
            ?TRACE(removed_goodbye, #{name => Name, type => Type, data => Data})
    end,
    {Name, Type};
store_entry({Name, Type, Data, Ttl, _CacheFlush}, Now) ->
    ExpiresAt = Now + Ttl * 1000,
    IsNew = ets:lookup(?TAB, {Name, Type, Data}) =:= [],
    ets:insert(?TAB, {{Name, Type, Data}, {ExpiresAt, Now}}),
    IsNew andalso
        ?TRACE(added, #{name => Name, type => Type, data => Data, ttl => Ttl}),
    {Name, Type}.

%% Answers and removes every waiter on {Name, Type}, if there's now
%% something to tell them - a touch that turned out to be a deletion
%% (a goodbye leaving nothing behind) wakes nobody up, since there's
%% nothing new to report; those waiters keep waiting for a real answer
%% or their own timeout.
notify_waiters({Name, Type}, State) ->
    case lookup(Name, Type) of
        [] ->
            State;
        Answers ->
            {Matching, Remaining} = maps:fold(
                fun(Ref, #{name := N, type := T} = Waiter, {M, R}) ->
                    case N =:= Name andalso T =:= Type of
                        true -> {M#{Ref => Waiter}, R};
                        false -> {M, R#{Ref => Waiter}}
                    end
                end,
                {#{}, #{}},
                State#state.waiters
            ),
            maps:foreach(
                fun(Ref, #{from := From, timer := Timer}) ->
                    cancel_timer(Timer),
                    erlang:demonitor(Ref, [flush]),
                    gen_server:reply(From, {ok, Answers})
                end,
                Matching
            ),
            State#state{waiters = Remaining}
    end.

schedule_await_timeout(infinity, _Ref) ->
    undefined;
schedule_await_timeout(TimeoutMs, Ref) ->
    erlang:send_after(TimeoutMs, self(), {await_timeout, Ref}).

cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    ok.

expire_rows() ->
    Now = now_ms(),
    case ets:select_delete(?TAB, [{{'_', {'$1', '_'}}, [{'=<', '$1', Now}], [true]}]) of
        0 -> ok;
        Count -> ?TRACE(expired, #{count => Count})
    end.

%% Oldest-InsertedAt-first eviction once over the configured cap. Only
%% runs when actually over the cap, so the full table scan is fine even
%% though it isn't the cheapest possible eviction strategy.
enforce_max_entries() ->
    MaxEntries = application:get_env(mdns_bridge, cache_max_entries, ?DEFAULT_MAX_ENTRIES),
    Size = ets:info(?TAB, size),
    case Size - MaxEntries of
        Excess when Excess > 0 ->
            evict_oldest(Excess);
        _ ->
            ok
    end.

%% Projects straight to {InsertedAt, Key} pairs via a match spec, rather
%% than copying every full row out with tab2list/1 just to pick the
%% InsertedAt back out of each one - and sorting {InsertedAt, Key} tuples
%% needs no comparator function, since standard term order already
%% compares them InsertedAt-first.
evict_oldest(N) ->
    ByAge = ets:select(?TAB, [{{'$1', {'_', '$2'}}, [], [{{'$2', '$1'}}]}]),
    ToEvict = lists:sublist(lists:sort(ByAge), N),
    [ets:delete(?TAB, Key) || {_InsertedAt, Key} <- ToEvict],
    ?TRACE(evicted, #{count => N, keys => [Key || {_InsertedAt, Key} <- ToEvict]}),
    ok.

now_ms() ->
    erlang:monotonic_time(millisecond).

remaining_seconds(ExpiresAt, Now) ->
    max(0, (ExpiresAt - Now) div 1000).
