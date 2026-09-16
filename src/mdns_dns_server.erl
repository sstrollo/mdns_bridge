%%%-------------------------------------------------------------------
%% @doc Classic unicast-DNS bridge for the `.local` domain. Listens on a
%% plain UDP port (not 53, not 5353) and answers A-record queries from
%% mdns_cache/mdns_query - this is the socket an upstream resolver (e.g.
%% Avassa's per-host nameserver) forwards `.local` queries to.
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

-define(SERVER, ?MODULE).
-define(DEFAULT_PORT, 8053).
-define(DEFAULT_BIND_IP, {0, 0, 0, 0}).
-define(DEFAULT_ANSWER_TTL, 30).
-define(DEFAULT_QUERY_TIMEOUT_MS, 400).
-define(LOCAL_SUFFIX, ".local").

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
    case is_local(Name) of
        false ->
            refused(Req);
        true when Type =:= a ->
            answer_a(Req, Name);
        true ->
            %% We only track A records in v1: answer NOERROR/no-data
            %% rather than asserting the name doesn't exist at all.
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

refused(#dns_rec{header = Header} = Req) ->
    Req#dns_rec{header = Header#dns_header{qr = 1, aa = 0, ra = 0, rcode = 5}}.

is_local(Name) ->
    lists:suffix(?LOCAL_SUFFIX, Name) orelse Name =:= "local".

reply(Socket, SrcIp, SrcPort, Response) ->
    Packet = inet_dns:encode(Response, false),
    gen_udp:send(Socket, SrcIp, SrcPort, Packet).
