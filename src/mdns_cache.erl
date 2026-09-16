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
%% (mdns_query's on-demand resolve) subscribe via await_subscribe/2 and
%% then simply wait for a `{mdns_answer, Name, Type, Answers}` message in
%% their own mailbox - notification happens inline with insert_many/1
%% handling, in this process.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_cache).

-behaviour(gen_server).

-export([
    child_spec/0,
    start_link/0,
    insert_many/1,
    lookup/2,
    near_expiry/1,
    await_subscribe/2,
    await_unsubscribe/2,
    dump/0,
    print/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(TAB, mdns_cache_tab).
-define(WAITERS, mdns_cache_waiters).
-define(SWEEP_INTERVAL_MS, 5000).
-define(FLUSH_GRACE_MS, 1000).
-define(DEFAULT_MAX_ENTRIES, 10000).

-record(state, {}).

%% Entry as produced by mdns_proto:extract_answers/1.
-type entry() :: {
    Name :: string(),
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
%% landed - and any matching await_subscribe/2 waiter notified - before
%% this returns.
-spec insert_many([entry()]) -> ok.
insert_many(Entries) ->
    gen_server:call(?SERVER, {insert_many, Entries}).

%% Direct ETS read: current, unexpired {Data, RemainingTtlSeconds} answers.
-spec lookup(string(), atom()) -> [{term(), non_neg_integer()}].
lookup(Name, Type) ->
    Now = now_ms(),
    [
        {Data, remaining_seconds(ExpiresAt, Now)}
     || [Data, ExpiresAt] <- ets:match(?TAB, {{Name, Type, '$1'}, {'$2', '_'}}),
        ExpiresAt > Now
    ].

%% {Name, Type} pairs with at least one unexpired entry due to expire
%% within WithinSeconds - candidates for proactive refresh.
-spec near_expiry(non_neg_integer()) -> [{string(), atom()}].
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

-spec await_subscribe(string(), atom()) -> ok.
await_subscribe(Name, Type) ->
    true = ets:insert(?WAITERS, {{Name, Type}, self()}),
    ok.

-spec await_unsubscribe(string(), atom()) -> ok.
await_unsubscribe(Name, Type) ->
    ets:delete_object(?WAITERS, {{Name, Type}, self()}),
    ok.

%% Direct ETS read: every current, unexpired entry - for inspecting the
%% cache from a shell (`rebar3 shell`) or a debug script. See print/0 for
%% a version that just formats this to stdout.
-spec dump() ->
    [
        #{
            name := string(),
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

%% Prints dump/0's result to stdout, one line per entry, sorted by
%% {Name, Type} for readability.
-spec print() -> ok.
print() ->
    Entries = lists:sort(
        fun(#{name := N1, type := T1}, #{name := N2, type := T2}) ->
            {N1, T1} =< {N2, T2}
        end,
        dump()
    ),
    [
        io:format("~-40s ~-6w ttl=~-6w age=~-6w ~p~n", [Name, Type, Ttl, Age, Data])
     || #{name := Name, type := Type, data := Data, ttl_remaining := Ttl, age := Age} <-
            Entries
    ],
    io:format("~p entries~n", [length(Entries)]).

init([]) ->
    ets:new(?TAB, [set, public, named_table, {read_concurrency, true}]),
    ets:new(?WAITERS, [bag, public, named_table]),
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {ok, #state{}}.

handle_call({insert_many, Entries}, _From, State) ->
    Now = now_ms(),
    FlushKeys = lists:usort([{Name, Type} || {Name, Type, _Data, _Ttl, true} <- Entries]),
    [flush_stale(Key, Now) || Key <- FlushKeys],
    Touched = lists:usort([store_entry(E, Now) || E <- Entries]),
    [notify_waiters(Name, Type) || {Name, Type} <- Touched],
    enforce_max_entries(),
    {reply, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(sweep, State) ->
    expire_rows(),
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {noreply, State};
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
            logger:debug("mdns_cache: cache-flush removed ~p stale entr(ies) for ~p/~p", [
                Count, Name, Type
            ])
    end.

store_entry({Name, Type, Data, 0, _CacheFlush}, _Now) ->
    %% mDNS goodbye packet: TTL=0 means "remove this record now".
    case ets:take(?TAB, {Name, Type, Data}) of
        [] ->
            ok;
        [_] ->
            logger:debug("mdns_cache: removed (goodbye) ~p/~p ~p", [Name, Type, Data])
    end,
    {Name, Type};
store_entry({Name, Type, Data, Ttl, _CacheFlush}, Now) ->
    ExpiresAt = Now + Ttl * 1000,
    IsNew = ets:lookup(?TAB, {Name, Type, Data}) =:= [],
    ets:insert(?TAB, {{Name, Type, Data}, {ExpiresAt, Now}}),
    IsNew andalso
        logger:debug("mdns_cache: added ~p/~p ~p (ttl=~p)", [Name, Type, Data, Ttl]),
    {Name, Type}.

notify_waiters(Name, Type) ->
    case ets:lookup(?WAITERS, {Name, Type}) of
        [] ->
            ok;
        Waiters ->
            Answers = lookup(Name, Type),
            [Pid ! {mdns_answer, Name, Type, Answers} || {_, Pid} <- Waiters],
            ets:delete(?WAITERS, {Name, Type})
    end.

expire_rows() ->
    Now = now_ms(),
    case ets:select_delete(?TAB, [{{'_', {'$1', '_'}}, [{'=<', '$1', Now}], [true]}]) of
        0 -> ok;
        Count -> logger:debug("mdns_cache: expired ~p entr(ies) (natural TTL)", [Count])
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

evict_oldest(N) ->
    Rows = ets:tab2list(?TAB),
    Sorted = lists:sort(
        fun({_, {_, InsertedAt1}}, {_, {_, InsertedAt2}}) ->
            InsertedAt1 =< InsertedAt2
        end,
        Rows
    ),
    ToEvict = lists:sublist(Sorted, N),
    [ets:delete(?TAB, Key) || {Key, _Value} <- ToEvict],
    logger:debug("mdns_cache: evicted ~p oldest entr(ies) (over cache_max_entries): ~p", [
        N, [Key || {Key, _Value} <- ToEvict]
    ]),
    ok.

now_ms() ->
    erlang:monotonic_time(millisecond).

remaining_seconds(ExpiresAt, Now) ->
    max(0, (ExpiresAt - Now) div 1000).
