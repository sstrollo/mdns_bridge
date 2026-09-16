%%%-------------------------------------------------------------------
%% @doc In-memory cache of records learned from mDNS traffic.
%%
%% Storage is a public ETS table keyed by {Name, Type, Data} so reads
%% (lookup/2, near_expiry/1) never have to go through the gen_server -
%% only inserts and the expiry sweep are serialized through this process.
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
    await_unsubscribe/2
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(TAB, mdns_cache_tab).
-define(WAITERS, mdns_cache_waiters).
-define(SWEEP_INTERVAL_MS, 5000).

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
     || [Data, ExpiresAt] <- ets:match(?TAB, {{Name, Type, '$1'}, '$2'}),
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
     || [Name, Type, ExpiresAt] <- ets:match(?TAB, {{'$1', '$2', '_'}, '$3'}),
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

init([]) ->
    ets:new(?TAB, [set, public, named_table, {read_concurrency, true}]),
    ets:new(?WAITERS, [bag, public, named_table]),
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), sweep),
    {ok, #state{}}.

handle_call({insert_many, Entries}, _From, State) ->
    Touched = lists:usort([store_entry(E) || E <- Entries]),
    [notify_waiters(Name, Type) || {Name, Type} <- Touched],
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

store_entry({Name, Type, Data, 0, _CacheFlush}) ->
    %% mDNS goodbye packet: TTL=0 means "remove this record now".
    ets:delete(?TAB, {Name, Type, Data}),
    {Name, Type};
store_entry({Name, Type, Data, Ttl, _CacheFlush}) ->
    ExpiresAt = now_ms() + Ttl * 1000,
    ets:insert(?TAB, {{Name, Type, Data}, ExpiresAt}),
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
    ets:select_delete(?TAB, [{{'_', '$1'}, [{'=<', '$1', Now}], [true]}]).

now_ms() ->
    erlang:monotonic_time(millisecond).

remaining_seconds(ExpiresAt, Now) ->
    max(0, (ExpiresAt - Now) div 1000).
