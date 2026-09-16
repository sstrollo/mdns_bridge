%%%-------------------------------------------------------------------
%% @doc Classic unicast-DNS bridge for the `.local` domain. Listens on a
%% plain UDP port (not 53, not 5353) and answers A-record queries from
%% mdns_cache/mdns_query - this is the socket an upstream resolver (e.g.
%% dnsmasq, systemd-resolved, or Erlang's own inet_db - see the README)
%% forwards `.local` queries to.
%%
%% For anything outside `.local` we deliberately reply NOERROR with an
%% empty answer section rather than REFUSED. That's not just politeness:
%% OTP's inet_res only falls back from its `nameservers` list to its
%% `alt_nameservers` list on NXDOMAIN or on an empty-but-OK answer, never
%% on REFUSED (see inet_res:query_nss_result/9 and res_query/5 in the
%% kernel app). Replying REFUSED would make this server usable as a
%% `.local`-only bridge but permanently break split-horizon setups that
%% put it in `nameservers` and a real resolver in `alt_nameservers`.
%%
%% Each request is handled in its own short-lived process so a slow
%% on-demand mDNS lookup for one query can't stall others - but that
%% means an unbounded flood of inbound packets would spawn an unbounded
%% number of processes, and each cache-miss `.local` query also puts a
%% multicast mDNS query out onto the LAN. dns_rate_limit_per_second caps
%% how many requests we'll actually act on per second (the rest are
%% simply dropped, same as a lost UDP packet); anyone who can reach this
%% port cannot use it to cheaply flood the multicast segment or exhaust
%% the process table beyond that budget.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_dns_server).

-behaviour(gen_server).

-include("mdns_dns.hrl").

-export([child_spec/0, start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([build_response/2, should_accept/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_PORT, 8053).
-define(DEFAULT_BIND_IP, {0, 0, 0, 0}).
-define(DEFAULT_ANSWER_TTL, 30).
-define(DEFAULT_QUERY_TIMEOUT_MS, 400).
-define(DEFAULT_RATE_LIMIT_PER_SECOND, 1000).
-define(RATE_WINDOW_MS, 1000).

-record(state, {
    socket :: gen_udp:socket(),
    rate_limit :: pos_integer() | infinity,
    count = 0 :: non_neg_integer()
}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    Port = application:get_env(mdns_bridge, dns_port, ?DEFAULT_PORT),
    BindIp = application:get_env(mdns_bridge, dns_bind_ip, ?DEFAULT_BIND_IP),
    RateLimit = application:get_env(
        mdns_bridge, dns_rate_limit_per_second, ?DEFAULT_RATE_LIMIT_PER_SECOND
    ),
    Opts = [binary, {active, true}, {reuseaddr, true}, {ip, BindIp}],
    case gen_udp:open(Port, Opts) of
        {ok, Socket} ->
            logger:info("mdns_dns_server: listening on ~p:~p", [BindIp, Port]),
            schedule_rate_reset(),
            {ok, #state{socket = Socket, rate_limit = RateLimit}};
        {error, Reason} ->
            {stop, {socket_open_failed, Reason}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(
    {udp, Socket, SrcIp, SrcPort, Packet},
    #state{socket = Socket, rate_limit = RateLimit, count = Count} = State
) ->
    case should_accept(RateLimit, Count) of
        true ->
            spawn(fun() -> handle_query(Socket, SrcIp, SrcPort, Packet) end),
            {noreply, State#state{count = Count + 1}};
        false ->
            %% Over budget for this window: drop it, same as a lost
            %% UDP packet - the caller's own retry/timeout handles it.
            {noreply, State}
    end;
handle_info(reset_rate_counter, State) ->
    schedule_rate_reset(),
    {noreply, State#state{count = 0}};
handle_info(_Msg, State) ->
    {noreply, State}.

%% Pure so it's unit-testable without a real socket or timing.
-spec should_accept(pos_integer() | infinity, non_neg_integer()) -> boolean().
should_accept(infinity, _Count) -> true;
should_accept(RateLimit, Count) -> Count < RateLimit.

schedule_rate_reset() ->
    erlang:send_after(?RATE_WINDOW_MS, self(), reset_rate_counter).

%% -- request handling (runs in its own process) ------------------------

handle_query(Socket, SrcIp, SrcPort, Packet) ->
    case inet_dns:decode(Packet, false) of
        {ok, #dns_rec{qdlist = [Q | _]} = Req} ->
            Response = build_response(Req, Q),
            reply(Socket, SrcIp, SrcPort, Response);
        {ok, #dns_rec{qdlist = []}} ->
            ok;
        {error, _Reason} ->
            ok
    end.

build_response(Req, #dns_query{domain = Domain, type = Type}) ->
    Name = mdns_proto:normalize_name(Domain),
    case mdns_proto:is_local(Name) andalso Type =:= a of
        true ->
            answer_a(Req, Name);
        false ->
            %% Not a `.local` A query: we have no opinion on it. NOERROR
            %% with no answers (rather than NXDOMAIN or REFUSED) is what
            %% lets a caller with alt_nameservers configured fall through
            %% to a real resolver for it - see the module doc.
            mdns_proto:dns_response(Req, [], Type, true)
    end.

answer_a(Req, Name) ->
    Timeout = application:get_env(mdns_bridge, query_timeout_ms, ?DEFAULT_QUERY_TIMEOUT_MS),
    AnswerTtlCap = application:get_env(mdns_bridge, answer_ttl, ?DEFAULT_ANSWER_TTL),
    Answers =
        case mdns_query:resolve(Name, a, Timeout) of
            {ok, Found} -> [{Data, min(Ttl, AnswerTtlCap)} || {Data, Ttl} <- Found];
            {error, timeout} -> []
        end,
    mdns_proto:dns_response(Req, Answers, a, Answers =/= []).

reply(Socket, SrcIp, SrcPort, Response) ->
    Packet = inet_dns:encode(Response, false),
    gen_udp:send(Socket, SrcIp, SrcPort, Packet).
