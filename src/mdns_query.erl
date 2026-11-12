-module(mdns_query).

-moduledoc """
Active mDNS querying: on-demand `resolve/3` (blocking, callable from
any process - used by the classic-DNS bridge on a cache miss) plus a
periodic sweep that proactively re-queries cache entries before their
TTL expires, so answers don't just silently go stale between the time
someone last overheard them.
""".

-behaviour(gen_server).

-export([child_spec/0, start_link/0, resolve/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(REFRESH_INTERVAL_MS, 15000).
-define(REFRESH_BEFORE_SECONDS, 20).
%% Questions per refresh packet: RFC 6762 allows many per query, and a
%% question is well under 300 bytes, so this keeps each packet
%% comfortably inside a normal MTU while turning a sweep over a busy
%% cache into a handful of packets instead of one per record.
-define(QUESTIONS_PER_PACKET, 20).

-record(state, {}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc """
Resolve Name/Type, issuing an mDNS query and waiting up to TimeoutMs
for an answer if it isn't already cached (see `mdns_cache:await/3` -
this just fires the query and blocks on that). Safe to call
concurrently from many processes - each call blocks independently, no
shared bottleneck.

A name registered via `mdns:register/2,3` is always answered from
`mdns_registry`, never from `mdns_cache`: we're the authority on our
own published records, regardless of what else the network might be
saying about that name (accidentally or otherwise).
""".
-spec resolve(string() | binary(), atom(), timeout()) ->
    {ok, [{term(), non_neg_integer()}]} | {error, timeout}.
resolve(Name0, Type, TimeoutMs) ->
    Name = mdns_proto:normalize_name(Name0),
    case mdns_registry:answers_for(Name, Type) of
        [] -> resolve_from_cache(Name, Type, TimeoutMs);
        Answers -> {ok, Answers}
    end.

resolve_from_cache(Name, Type, TimeoutMs) ->
    case mdns_cache:lookup(Name, Type) of
        [] -> resolve_miss(Name, Type, TimeoutMs);
        Answers -> {ok, Answers}
    end.

%% mdns_cache:await/3 re-checks the cache itself before deciding to wait,
%% so there's no race to get right here regardless of the order between
%% these two calls - firing off the query first just means it has a
%% head start.
resolve_miss(Name, Type, TimeoutMs) ->
    mdns_socket:send_query(Name, Type),
    mdns_cache:await(Name, Type, TimeoutMs).

init([]) ->
    schedule_sweep(),
    {ok, #state{}}.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refresh_sweep, State) ->
    send_in_batches(mdns_cache:near_expiry(?REFRESH_BEFORE_SECONDS)),
    schedule_sweep(),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

send_in_batches([]) ->
    ok;
send_in_batches(Keys) when length(Keys) > ?QUESTIONS_PER_PACKET ->
    {Batch, Rest} = lists:split(?QUESTIONS_PER_PACKET, Keys),
    mdns_socket:send_queries(Batch),
    send_in_batches(Rest);
send_in_batches(Keys) ->
    mdns_socket:send_queries(Keys).

schedule_sweep() ->
    erlang:send_after(?REFRESH_INTERVAL_MS, self(), refresh_sweep).
