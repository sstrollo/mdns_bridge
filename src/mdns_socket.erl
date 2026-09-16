%%%-------------------------------------------------------------------
%% @doc Owns the mDNS multicast UDP socket (224.0.0.251:5353). Decodes
%% inbound packets: feeds any answer records into mdns_cache, and answers
%% any question that matches something mdns_registry has published.
%% Exposes send_query/2 (mdns_query's active querying) and announce/3
%% (mdns_registry's announcements, reactive answers, and goodbyes).
%% @end
%%%-------------------------------------------------------------------
-module(mdns_socket).

-behaviour(gen_server).

-include("mdns_dns.hrl").

-export([child_spec/0, start_link/0, send_query/2, announce/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(MDNS_GROUP, {224, 0, 0, 251}).
-define(MDNS_PORT, 5353).

-record(state, {socket :: gen_udp:socket()}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec send_query(string(), atom()) -> ok.
send_query(Name, Type) ->
    gen_server:cast(?SERVER, {send_query, Name, Type}).

%% Multicast an mDNS answer for Name/Type: an announce, a reactive
%% response, or (with a Ttl of 0 in Answers) a goodbye.
-spec announce(string(), atom(), [{term(), non_neg_integer()}]) -> ok.
announce(Name, Type, Answers) ->
    gen_server:cast(?SERVER, {announce, Name, Type, Answers}).

init([]) ->
    IfaceConfig = application:get_env(mdns, interface, undefined),
    case mdns_iface:resolve(IfaceConfig) of
        {ok, IfaceIp} ->
            case open_socket(IfaceIp) of
                {ok, Socket} ->
                    logger:info(
                        "mdns_socket: joined ~p on interface ~p",
                        [?MDNS_GROUP, IfaceIp]
                    ),
                    {ok, #state{socket = Socket}};
                {error, Reason} ->
                    {stop, {socket_open_failed, Reason}}
            end;
        {error, Reason} ->
            {stop, {interface_resolve_failed, Reason}}
    end.

open_socket(IfaceIp) ->
    Opts = [
        binary,
        {active, true},
        {reuseaddr, true},
        {ip, {0, 0, 0, 0}},
        {add_membership, {?MDNS_GROUP, IfaceIp}},
        {multicast_if, IfaceIp},
        {multicast_ttl, 255},
        {multicast_loop, true}
    ],
    gen_udp:open(?MDNS_PORT, Opts).

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({send_query, Name, Type}, State) ->
    Rec = mdns_proto:mdns_query(Name, Type),
    do_send(Rec, State),
    {noreply, State};
handle_cast({announce, Name, Type, Answers}, State) ->
    Rec = mdns_proto:mdns_answer(Name, Type, Answers),
    do_send(Rec, State),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, _SrcIp, _SrcPort, Packet}, #state{socket = Socket} = State) ->
    case inet_dns:decode(Packet, true) of
        {ok, DnsRec} ->
            case mdns_proto:extract_answers(DnsRec) of
                [] -> ok;
                Entries -> mdns_cache:insert_many(Entries)
            end,
            answer_registered_questions(DnsRec, State);
        {error, _Reason} ->
            ok
    end,
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- internal -----------------------------------------------------------

answer_registered_questions(#dns_rec{qdlist = Qd}, State) ->
    [answer_if_registered(Q, State) || Q <- Qd],
    ok.

answer_if_registered(#dns_query{domain = Domain, type = Type}, State) ->
    Name = mdns_proto:normalize_name(Domain),
    case mdns_registry:answers_for(Name, Type) of
        [] ->
            ok;
        Answers ->
            do_send(mdns_proto:mdns_answer(Name, Type, Answers), State)
    end.

do_send(Rec, State) ->
    Packet = inet_dns:encode(Rec, true),
    gen_udp:send(State#state.socket, ?MDNS_GROUP, ?MDNS_PORT, Packet).
