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
%% on-demand mDNS lookup for one query can't stall others.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_dns_server).

-behaviour(gen_server).

-include("mdns_dns.hrl").

-export([child_spec/0, start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([build_response/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_PORT, 8053).
-define(DEFAULT_BIND_IP, {0, 0, 0, 0}).
-define(DEFAULT_ANSWER_TTL, 30).
-define(DEFAULT_QUERY_TIMEOUT_MS, 400).

-record(state, {socket :: gen_udp:socket()}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    Port = application:get_env(mdns, dns_port, ?DEFAULT_PORT),
    BindIp = application:get_env(mdns, dns_bind_ip, ?DEFAULT_BIND_IP),
    Opts = [binary, {active, true}, {reuseaddr, true}, {ip, BindIp}],
    case gen_udp:open(Port, Opts) of
        {ok, Socket} ->
            logger:info("mdns_dns_server: listening on ~p:~p", [BindIp, Port]),
            {ok, #state{socket = Socket}};
        {error, Reason} ->
            {stop, {socket_open_failed, Reason}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, SrcIp, SrcPort, Packet}, #state{socket = Socket} = State) ->
    spawn(fun() -> handle_query(Socket, SrcIp, SrcPort, Packet) end),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

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
    Timeout = application:get_env(mdns, query_timeout_ms, ?DEFAULT_QUERY_TIMEOUT_MS),
    AnswerTtlCap = application:get_env(mdns, answer_ttl, ?DEFAULT_ANSWER_TTL),
    Answers =
        case mdns_query:resolve(Name, a, Timeout) of
            {ok, Found} -> [{Data, min(Ttl, AnswerTtlCap)} || {Data, Ttl} <- Found];
            {error, timeout} -> []
        end,
    mdns_proto:dns_response(Req, Answers, a, Answers =/= []).

reply(Socket, SrcIp, SrcPort, Response) ->
    Packet = inet_dns:encode(Response, false),
    gen_udp:send(Socket, SrcIp, SrcPort, Packet).
