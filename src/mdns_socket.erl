%%%-------------------------------------------------------------------
%% @doc Owns the mDNS multicast UDP socket (224.0.0.251:5353). Decodes
%% inbound packets: feeds any answer records into mdns_cache, flags any
%% answer that conflicts with something mdns_registry has published
%% (ongoing conflict defense, RFC 6762 section 9), answers any question
%% that matches something mdns_registry has published, and notifies any
%% probe watchers (mdns_registry's RFC 6762 section 8 probing) of
%% matching answers or competing simultaneous probes.
%%
%% Exposes send_query/2 (mdns_query's active querying), announce/3
%% (mdns_registry's announcements, reactive answers, and goodbyes),
%% send_probe/4 and probe_subscribe/2 + probe_unsubscribe/2 (mdns_registry's
%% probing - see its module doc). Probe watchers live in this process's
%% own state (a map, monitoring each subscriber so a caller that crashes
%% mid-probe doesn't leak its entry) rather than a separate ETS table -
%% subscribe/unsubscribe happen once per probe, nowhere near hot enough
%% to need direct ETS access instead of going through the gen_server.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_socket).

-behaviour(gen_server).

-include("mdns_dns.hrl").

-export([
    child_spec/0,
    start_link/0,
    send_query/2,
    announce/3,
    send_probe/4,
    probe_subscribe/2,
    probe_unsubscribe/2,
    refresh_interface/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(MDNS_GROUP, {224, 0, 0, 251}).
-define(MDNS_PORT, 5353).

%% {Pid, monitor ref watching it} per subscriber of a {Name, Type} -
%% the ref lets a subscriber be found and demonitored again by
%% probe_unsubscribe/2, or dropped on its own on a 'DOWN'.
-type probe_watchers() :: #{{string(), atom()} => [{pid(), reference()}]}.

-record(state, {
    socket :: gen_udp:socket(),
    iface_ip :: inet:ip4_address(),
    probe_watchers = #{} :: probe_watchers()
}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec send_query(binary(), atom()) -> ok.
send_query(Name, Type) ->
    gen_server:cast(?SERVER, {send_query, Name, Type}).

%% Multicast an mDNS answer for Name/Type: an announce, a reactive
%% response, or (with a Ttl of 0 in Answers) a goodbye.
-spec announce(binary(), atom(), [{term(), non_neg_integer()}]) -> ok.
announce(Name, Type, Answers) ->
    gen_server:cast(?SERVER, {announce, Name, Type, Answers}).

%% Multicast an RFC 6762 8.1 probe for Name/Type/Data.
-spec send_probe(binary(), atom(), term(), non_neg_integer()) -> ok.
send_probe(Name, Type, Data, Ttl) ->
    gen_server:cast(?SERVER, {send_probe, Name, Type, Data, Ttl}).

%% Register the calling process to receive
%% `{mdns_probe_seen, Name, Type, Data}' for every answer or competing
%% probe seen on the wire for Name/Type - used by mdns_registry while
%% probing a name (see its module doc). Unlike mdns_cache:await/3, this
%% genuinely needs a stream of every matching packet over the whole
%% probe window, not just a single eventual answer, so a plain
%% subscription - not a blocking wait - is the right shape here; the
%% messages still land directly in the caller's own mailbox, exactly as
%% before. A gen_server:call, not a cast: the caller needs to know the
%% subscription has actually taken effect before it starts probing (and,
%% for unsubscribe, that no further message can arrive) - the same
%% synchronous guarantee direct ETS access used to give for free.
-spec probe_subscribe(binary(), atom()) -> ok.
probe_subscribe(Name, Type) ->
    gen_server:call(?SERVER, {probe_subscribe, Name, Type}).

-spec probe_unsubscribe(binary(), atom()) -> ok.
probe_unsubscribe(Name, Type) ->
    gen_server:call(?SERVER, {probe_unsubscribe, Name, Type}).

%% Call when the embedding system detects that the configured
%% interface's address changed (e.g. a DHCP renewal) - this app does not
%% watch for that itself. Rejoins the multicast group on the new address
%% if it actually changed; a no-op otherwise.
-spec refresh_interface() -> ok | {error, term()}.
refresh_interface() ->
    gen_server:call(?SERVER, refresh_interface).

init([]) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve(IfaceConfig) of
        {ok, IfaceIp} ->
            case open_socket(IfaceIp) of
                {ok, Socket} ->
                    logger:info(
                        "mdns_socket: joined ~p on interface ~p",
                        [?MDNS_GROUP, IfaceIp]
                    ),
                    {ok, #state{socket = Socket, iface_ip = IfaceIp}};
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
        %% Without this, binding 5353 fails with eaddrinuse on any host
        %% that already runs its own mDNS responder on the same port -
        %% notably macOS's built-in mDNSResponder (Bonjour), which itself
        %% binds with SO_REUSEPORT specifically so other mDNS-aware
        %% processes can coexist with it. Not supported on Windows - not
        %% a target platform for this app.
        {reuseport, true},
        {ip, {0, 0, 0, 0}},
        {add_membership, {?MDNS_GROUP, IfaceIp}},
        {multicast_if, IfaceIp},
        {multicast_ttl, 255},
        {multicast_loop, true}
    ],
    gen_udp:open(?MDNS_PORT, Opts).

handle_call(refresh_interface, _From, State) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve(IfaceConfig) of
        {ok, NewIp} when NewIp =/= State#state.iface_ip ->
            OldIp = State#state.iface_ip,
            ok = inet:setopts(State#state.socket, [{drop_membership, {?MDNS_GROUP, OldIp}}]),
            ok = inet:setopts(State#state.socket, [
                {add_membership, {?MDNS_GROUP, NewIp}}, {multicast_if, NewIp}
            ]),
            logger:info("mdns_socket: interface changed ~p -> ~p", [OldIp, NewIp]),
            {reply, ok, State#state{iface_ip = NewIp}};
        {ok, _UnchangedIp} ->
            {reply, ok, State};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call({probe_subscribe, Name, Type}, {FromPid, _Tag}, State) ->
    Ref = erlang:monitor(process, FromPid),
    Watchers = maps:update_with(
        {Name, Type},
        fun(W) -> [{FromPid, Ref} | W] end,
        [{FromPid, Ref}],
        State#state.probe_watchers
    ),
    {reply, ok, State#state{probe_watchers = Watchers}};
handle_call({probe_unsubscribe, Name, Type}, {FromPid, _Tag}, State) ->
    {reply, ok, remove_watcher(Name, Type, FromPid, State)};
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
handle_cast({send_probe, Name, Type, Data, Ttl}, State) ->
    Rec = mdns_proto:probe_query(Name, Type, Data, Ttl),
    do_send(Rec, State),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, _SrcIp, _SrcPort, Packet}, #state{socket = Socket} = State) ->
    case inet_dns:decode(Packet, true) of
        {ok, DnsRec} ->
            case mdns_proto:extract_answers(DnsRec) of
                [] ->
                    ok;
                Entries ->
                    mdns_cache:insert_many(Entries),
                    check_conflicts(Entries)
            end,
            notify_probe_watchers(mdns_proto:extract_watched_records(DnsRec), State),
            answer_registered_questions(DnsRec, State);
        {error, _Reason} ->
            ok
    end,
    {noreply, State};
handle_info({'DOWN', Ref, process, Pid, _Reason}, State) ->
    {noreply, State#state{probe_watchers = drop_watcher(Pid, Ref, State#state.probe_watchers)}};
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- internal -----------------------------------------------------------

%% RFC 6762 section 9 (ongoing conflict defense): flag any answer for a
%% name/type we currently publish whose data isn't one of our own current
%% values for it - i.e. some other, unrelated host is answering for a
%% name we own. (An answer that just repeats one of our own registered
%% values - e.g. a legitimate second registration under the same name,
%% for round-robin - is not a conflict.)
%%
%% PTR is excluded: it's RFC 6763's "shared" record type (both the
%% per-service-type enumeration PTR and the meta-enumeration PTR), where
%% many different, simultaneously valid owners contributing different
%% data under the same name is the normal case, not a conflict.
check_conflicts(Entries) ->
    [maybe_notify_conflict(Entry) || Entry <- Entries],
    ok.

maybe_notify_conflict({_Name, ptr, _Data, _Ttl, _CacheFlush}) ->
    ok;
maybe_notify_conflict({Name, Type, Data, _Ttl, _CacheFlush}) ->
    case mdns_registry:answers_for(Name, Type) of
        [] ->
            ok;
        Ours ->
            case lists:keymember(Data, 1, Ours) of
                true -> ok;
                false -> mdns_registry:notify_conflict(Name, Type, Data)
            end
    end.

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

notify_probe_watchers(Records, State) ->
    [notify_one_probe_watcher(R, State) || R <- Records],
    ok.

notify_one_probe_watcher({Name, Type, Data, _Ttl, _CacheFlush}, State) ->
    case maps:get({Name, Type}, State#state.probe_watchers, []) of
        [] -> ok;
        Watchers -> [Pid ! {mdns_probe_seen, Name, Type, Data} || {Pid, _Ref} <- Watchers]
    end.

%% Removes Pid's watch on {Name, Type} specifically (probe_unsubscribe/2)
%% - demonitoring it, so a 'DOWN' for it can't arrive after the fact.
remove_watcher(Name, Type, Pid, State) ->
    Key = {Name, Type},
    case maps:get(Key, State#state.probe_watchers, []) of
        [] ->
            State;
        Watchers ->
            {ToRemove, Remaining} = lists:partition(fun({P, _Ref}) -> P =:= Pid end, Watchers),
            [erlang:demonitor(Ref, [flush]) || {_Pid, Ref} <- ToRemove],
            State#state{probe_watchers = put_or_remove(Key, Remaining, State#state.probe_watchers)}
    end.

%% Removes whatever {Pid, Ref} watch this 'DOWN' belongs to, wherever it
%% is - a crashed caller may have died before ever calling
%% probe_unsubscribe/2, and this is what stops that from leaking.
drop_watcher(Pid, Ref, Watchers) ->
    maps:fold(
        fun(Key, W, Acc) ->
            put_or_remove(Key, lists:delete({Pid, Ref}, W), Acc)
        end,
        Watchers,
        Watchers
    ).

put_or_remove(Key, [], Map) -> maps:remove(Key, Map);
put_or_remove(Key, Watchers, Map) -> Map#{Key => Watchers}.

do_send(Rec, State) ->
    Packet = inet_dns:encode(Rec, true),
    gen_udp:send(State#state.socket, ?MDNS_GROUP, ?MDNS_PORT, Packet).
