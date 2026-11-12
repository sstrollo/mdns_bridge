-module(mdns_socket).

-moduledoc """
Owns the mDNS multicast UDP socket (224.0.0.251:5353). Decodes
inbound packets: feeds answer records into `mdns_cache`, flags any
answer that conflicts with something `mdns_registry` has published
(ongoing conflict defense, RFC 6762 section 9), answers any question
that matches something `mdns_registry` has published, and notifies any
probe watchers (`mdns_registry`'s RFC 6762 section 8 probing) of
matching answers or competing simultaneous probes.

Only packets from the local link are looked at (RFC 6762 section 11:
the source must be on the configured interface's subnet, or
169.254/16), and a response is only believed if it came from port
5353 (section 6) - the two checks that stop a host that isn't on the
link from unicasting records into the cache. Records that merely
appear inside a *query* (a known-answer list, a probe's proposal) are
never cached, and neither are this app's own registered records as
they loop back through the group - those are answered from the
registry. The socket runs in `{active, N}` mode so a flood can't grow
this process's mailbox without bound.

Exposes `send_query/2` (`mdns_query`'s active querying), `announce/3`
(`mdns_registry`'s announcements, reactive answers, and goodbyes),
`send_probe/4` and `probe_subscribe/2` + `probe_unsubscribe/2`
(`mdns_registry`'s probing - see its module doc). Probe watchers live
in this process's own state (a map, monitoring each subscriber so a
caller that crashes mid-probe doesn't leak its entry) rather than a
separate ETS table - subscribe/unsubscribe happen once per probe,
nowhere near hot enough to need direct ETS access instead of going
through the gen_server.
""".

-behaviour(gen_server).

-include("mdns_dns.hrl").
-include("mdns_trace.hrl").

-export([
    child_spec/0,
    start_link/0,
    send_query/2,
    send_queries/1,
    announce/3,
    announce_records/1,
    send_probe/4,
    probe_subscribe/2,
    probe_unsubscribe/2,
    refresh_interface/0,
    sync/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(MDNS_GROUP, {224, 0, 0, 251}).
-define(MDNS_PORT, 5353).
%% {active, N}: how many datagrams the socket may deliver before it
%% pauses until this process asks for more - bounds the mailbox under a
%% flood, at the cost of one setopts call per N packets.
-define(ACTIVE_N, 100).
%% RFC 6762 section 6: a given record must not be multicast more than
%% once per second (except in response to a probe) - otherwise every
%% query on the segment, legitimate or not, costs everyone a multicast
%% response.
-define(MIN_MULTICAST_INTERVAL_MS, 1000).
%% The last-multicast map is pruned of stale entries once it grows past
%% this, so it stays bounded by the number of distinct records actually
%% answered for recently, not by everything ever answered.
-define(RECENT_PRUNE_SIZE, 256).

%% {Pid, monitor ref watching it} per subscriber of a {Name, Type} -
%% the ref lets a subscriber be found and demonitored again by
%% probe_unsubscribe/2, or dropped on its own on a 'DOWN'.
-type probe_watchers() :: #{{binary(), atom()} => [{pid(), reference()}]}.

-record(state, {
    socket :: gen_udp:socket(),
    iface_ip :: inet:ip4_address(),
    netmask :: inet:ip4_address(),
    probe_watchers = #{} :: probe_watchers(),
    %% {Name, Type} -> monotonic ms it was last multicast (an answer or
    %% an announcement) - see ?MIN_MULTICAST_INTERVAL_MS.
    recent_multicast = #{} :: #{{binary(), atom()} => integer()}
}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc "Multicast an mDNS query for Type records of Name.".
-spec send_query(binary(), atom()) -> ok.
send_query(Name, Type) ->
    send_queries([{Name, Type}]).

-doc "Multicast one mDNS query packet carrying a question per `{Name, Type}`.".
-spec send_queries([{binary(), atom()}]) -> ok.
send_queries(Questions) ->
    gen_server:cast(?SERVER, {send_queries, Questions}).

-doc """
Multicast an mDNS answer for Name/Type: an announce, a reactive
response, or (with a Ttl of 0 in Answers) a goodbye.
""".
-spec announce(binary(), atom(), [{term(), non_neg_integer()}]) -> ok.
announce(Name, Type, Answers) ->
    announce_records([{Name, Type, Data, Ttl} || {Data, Ttl} <- Answers]).

-doc """
Multicast one announcement packet carrying every record in Records
(any mix of names and types) - `mdns_registry`'s periodic
re-announcement of everything it holds, in a few packets rather than
one per record.
""".
-spec announce_records([mdns_proto:record()]) -> ok.
announce_records(Records) ->
    gen_server:cast(?SERVER, {announce_records, Records}).

-doc "Multicast an RFC 6762 8.1 probe for Name/Type/Data.".
-spec send_probe(binary(), atom(), term(), non_neg_integer()) -> ok.
send_probe(Name, Type, Data, Ttl) ->
    gen_server:cast(?SERVER, {send_probe, Name, Type, Data, Ttl}).

-doc """
Register the calling process to receive
`{mdns_probe_seen, Name, Type, Data}` for every answer or competing
probe seen on the wire for Name/Type, until `probe_unsubscribe/2` is
called - used by `mdns_registry` while probing a name (see its module
doc). The caller's subscription has taken effect by the time this
returns.
""".
-spec probe_subscribe(binary(), atom()) -> ok.
probe_subscribe(Name, Type) ->
    gen_server:call(?SERVER, {probe_subscribe, Name, Type}).

-doc "Stop the calling process's `probe_subscribe/2` subscription to Name/Type.".
-spec probe_unsubscribe(binary(), atom()) -> ok.
probe_unsubscribe(Name, Type) ->
    gen_server:call(?SERVER, {probe_unsubscribe, Name, Type}).

-doc """
Call when the embedding system detects that the configured
interface's address changed (e.g. a DHCP renewal) - this app does not
watch for that itself. Rejoins the multicast group on the new address
if it actually changed; a no-op otherwise.
""".
-spec refresh_interface() -> ok | {error, term()}.
refresh_interface() ->
    gen_server:call(?SERVER, refresh_interface).

-doc """
Returns once every send requested before this call (`send_query/2`,
`announce/3`, `send_probe/4` - all casts) has been handed to the
socket. Used by `mdns_app:prep_stop/1` so shutdown goodbyes are
actually on the wire before the socket is closed.
""".
-spec sync() -> ok.
sync() ->
    gen_server:call(?SERVER, sync).

init([]) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve_with_netmask(IfaceConfig) of
        {ok, {IfaceIp, Netmask}} ->
            case open_socket(IfaceIp) of
                {ok, Socket} ->
                    logger:info(
                        "mdns_socket: joined ~0p on interface ~0p",
                        [?MDNS_GROUP, IfaceIp]
                    ),
                    {ok, #state{socket = Socket, iface_ip = IfaceIp, netmask = Netmask}};
                {error, Reason} ->
                    {stop, {socket_open_failed, Reason}}
            end;
        {error, Reason} ->
            {stop, {interface_resolve_failed, Reason}}
    end.

open_socket(IfaceIp) ->
    Opts = [
        binary,
        {active, ?ACTIVE_N},
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

handle_call(refresh_interface, _From, #state{socket = Socket, iface_ip = OldIp} = State) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve_with_netmask(IfaceConfig) of
        {ok, {NewIp, Netmask}} when NewIp =/= OldIp ->
            %% Leaving the group on the old address is best-effort: by
            %% the time the embedder calls this, that address has usually
            %% already gone away (which is why it's calling), and
            %% dropping a membership on a vanished address fails - that
            %% must not take this process (and its probe watchers) down.
            case inet:setopts(Socket, [{drop_membership, {?MDNS_GROUP, OldIp}}]) of
                ok ->
                    ok;
                {error, DropReason} ->
                    logger:info("mdns_socket: could not leave group on ~0p (~0p), continuing", [
                        OldIp, DropReason
                    ])
            end,
            case
                inet:setopts(Socket, [{add_membership, {?MDNS_GROUP, NewIp}}, {multicast_if, NewIp}])
            of
                ok ->
                    logger:info("mdns_socket: interface changed ~0p -> ~0p", [OldIp, NewIp]),
                    {reply, ok, State#state{iface_ip = NewIp, netmask = Netmask}};
                {error, JoinReason} ->
                    logger:warning("mdns_socket: could not join group on ~0p: ~0p", [
                        NewIp, JoinReason
                    ]),
                    {reply, {error, {join_failed, NewIp, JoinReason}}, State}
            end;
        {ok, {_UnchangedIp, Netmask}} ->
            {reply, ok, State#state{netmask = Netmask}};
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
handle_call(sync, _From, State) ->
    {reply, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({send_queries, Questions}, State) ->
    do_send(mdns_proto:mdns_query(Questions), State),
    {noreply, State};
handle_cast({announce_records, Records}, State) ->
    do_send(mdns_proto:mdns_response(Records, []), State),
    {noreply, note_multicast([{Name, Type} || {Name, Type, _, _} <- Records], State)};
handle_cast({send_probe, Name, Type, Data, Ttl}, State) ->
    Rec = mdns_proto:probe_query(Name, Type, Data, Ttl),
    do_send(Rec, State),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, SrcIp, SrcPort, Packet}, #state{socket = Socket} = State) ->
    %% Nothing that arrives on this socket may take the process down:
    %% anyone on the segment can send anything, and inet_dns:decode/2
    %% only turns *some* malformed input into {error, _} - a crafted
    %% datagram can make it raise instead. The whole per-packet path is
    %% guarded, not just decode, since the same holds for whatever a
    %% decoded-but-nonsensical packet can trip further down.
    NewState =
        try
            handle_packet(SrcIp, SrcPort, Packet, State)
        catch
            Class:Reason ->
                logger:debug("mdns_socket: dropped packet from ~0p:~b: ~0p", [
                    SrcIp, SrcPort, {Class, Reason}
                ]),
                State
        end,
    {noreply, NewState};
handle_info({udp_passive, Socket}, #state{socket = Socket} = State) ->
    ok = inet:setopts(Socket, [{active, ?ACTIVE_N}]),
    {noreply, State};
handle_info({'DOWN', Ref, process, Pid, _Reason}, State) ->
    {noreply, State#state{probe_watchers = drop_watcher(Pid, Ref, State#state.probe_watchers)}};
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- internal -----------------------------------------------------------

%% RFC 6762 section 11: only packets from the local link are considered
%% at all. Anything else is an off-link host unicasting at port 5353 -
%% the one way such a host could get records into the cache or trip
%% conflict handling.
handle_packet(SrcIp, SrcPort, Packet, #state{iface_ip = IfaceIp, netmask = Netmask} = State) ->
    case mdns_iface:is_link_local(SrcIp, IfaceIp, Netmask) of
        true ->
            case inet_dns:decode(Packet, true) of
                {ok, DnsRec} -> handle_decoded(DnsRec, SrcIp, SrcPort, State);
                {error, _Reason} -> State
            end;
        false ->
            ?TRACE(dropped_off_link, #{src => SrcIp, port => SrcPort}),
            State
    end.

%% A response is only believed if it came from port 5353 (RFC 6762
%% section 6: responses from any other source port MUST be ignored - they
%% can't be from an mDNS responder). A query's own records are never
%% cached: its answer section is the querier's known-answer list (7.1),
%% its authority section a prober's tentative proposal (8.1) - neither is
%% an assertion by the record's owner, though both are what a prober
%% watching for competition needs to see.
handle_decoded(#dns_rec{header = #dns_header{qr = IsResponse}} = DnsRec, SrcIp, SrcPort, State) ->
    case {IsResponse, SrcPort} of
        {true, ?MDNS_PORT} ->
            Entries = mdns_proto:extract_answers(DnsRec),
            notify_probe_watchers(Entries, State),
            case foreign_entries(Entries) of
                [] -> ok;
                Foreign -> mdns_cache:insert_many(Foreign)
            end,
            State;
        {true, _OtherPort} ->
            ?TRACE(dropped_response_port, #{src => SrcIp, port => SrcPort}),
            State;
        {false, _} ->
            notify_probe_watchers(mdns_proto:extract_watched_records(DnsRec), State),
            answer_registered_questions(DnsRec, SrcIp, SrcPort, State)
    end.

%% Everything in Entries except our own registered records. Those loop
%% back through the multicast group like anyone else's, but they're
%% answered from the registry, never the cache - and cached, they'd have
%% mdns_query's refresh sweep re-querying our own names. The one registry
%% lookup this takes per record also serves RFC 6762 section 9 (ongoing
%% conflict defense): a record for a name/type we publish whose data
%% isn't one of our own current values is some other host answering for
%% our name. (One that repeats one of our values - e.g. a legitimate
%% second registration under the same name, for round-robin - is ours.)
foreign_entries(Entries) ->
    [Entry || Entry <- Entries, not is_ours(Entry)].

is_ours({Name, Type, Data, Ttl, _CacheFlush}) ->
    case mdns_registry:answers_for(Name, Type) of
        [] ->
            false;
        Ours ->
            case lists:keymember(Data, 1, Ours) of
                true ->
                    true;
                false ->
                    maybe_notify_conflict(Name, Type, Data, Ttl),
                    false
            end
    end.

%% PTR is excluded: it's RFC 6763's "shared" record type (both the
%% per-service-type enumeration PTR and the meta-enumeration PTR), where
%% many different, simultaneously valid owners contributing different
%% data under the same name is the normal case, not a conflict.
%%
%% A goodbye (TTL 0) is excluded too: it withdraws a claim rather than
%% making one, so it can't conflict with ours. Not least our *own*
%% goodbyes, which loop back here: once a sibling registration under a
%% name we still hold has been withdrawn, its data is no longer among our
%% current values, so its goodbye would otherwise read as a competing
%% claim - and two of those within the defense grace window would make
%% mdns_registry give up the surviving registration.
maybe_notify_conflict(_Name, ptr, _Data, _Ttl) ->
    ok;
maybe_notify_conflict(_Name, _Type, _Data, 0) ->
    ok;
maybe_notify_conflict(Name, Type, Data, _Ttl) ->
    mdns_registry:notify_conflict(Name, Type, Data).

%% Answers every question in the packet that a registered record
%% satisfies. How the answer is sent depends on who asked (RFC 6762):
%% - from a source port other than 5353: a legacy unicast query (6.7) -
%%   a plain DNS client, answered by unicast in classic-DNS form;
%% - a QU question (5.4): answered by unicast to the querier;
%% - otherwise multicast, so every cache on the segment benefits - but
%%   never the same record more than once a second (section 6), except
%%   to answer a probe (one that carries proposals in its authority
%%   section), where the prober's whole point is to hear from us now.
answer_registered_questions(
    #dns_rec{header = Header, qdlist = Qd, nslist = Ns}, SrcIp, SrcPort, State
) ->
    IsProbe = Ns =/= [],
    lists:foldl(
        fun(Q, S) -> answer_if_registered(Q, Header, IsProbe, SrcIp, SrcPort, S) end, State, Qd
    ).

answer_if_registered(
    #dns_query{domain = Domain, type = Type, unicast_response = QU} = Q,
    Header,
    IsProbe,
    SrcIp,
    SrcPort,
    State
) ->
    Name = mdns_proto:normalize_wire_name(Domain),
    case registered_records(Name, Type) of
        [] ->
            State;
        An when SrcPort =/= ?MDNS_PORT ->
            do_send_to(
                mdns_proto:legacy_answer(Header, Q, An, additionals(An)), SrcIp, SrcPort, State
            ),
            State;
        An when QU ->
            do_send_to(mdns_proto:mdns_response(An, additionals(An)), SrcIp, SrcPort, State),
            State;
        An ->
            case not_recently_multicast(An, IsProbe, State) of
                [] ->
                    State;
                Send ->
                    do_send(mdns_proto:mdns_response(Send, additionals(Send)), State),
                    note_multicast([{N, T} || {N, T, _, _} <- Send], State)
            end
    end.

registered_records(Name, any) ->
    [{Name, Type, Data, Ttl} || {Type, Data, Ttl} <- mdns_registry:records_for(Name)];
registered_records(Name, Type) ->
    [{Name, Type, Data, Ttl} || {Data, Ttl} <- mdns_registry:answers_for(Name, Type)].

%% RFC 6763 section 12: a PTR answer should carry the instance's SRV and
%% TXT, and an SRV answer (given or implied) the target host's A record,
%% so a browser doesn't need a round trip per record - as far as we
%% publish them ourselves.
additionals(An) ->
    FromPtr = [R || {_, ptr, Instance, _} <- An, R <- srv_and_txt_of(Instance)],
    FromSrv = [R || {_, srv, {_, _, _, Host}, _} <- An ++ FromPtr, R <- a_of(Host)],
    lists:usort(FromPtr ++ FromSrv) -- An.

srv_and_txt_of(Name) ->
    [
        {Name, Type, Data, Ttl}
     || {Type, Data, Ttl} <- mdns_registry:records_for(Name), Type =:= srv orelse Type =:= txt
    ].

a_of(Name) ->
    [{Name, a, Data, Ttl} || {Data, Ttl} <- mdns_registry:answers_for(Name, a)].

not_recently_multicast(An, true = _IsProbe, _State) ->
    An;
not_recently_multicast(An, false, #state{recent_multicast = Recent}) ->
    Now = erlang:monotonic_time(millisecond),
    [
        R
     || {Name, Type, _, _} = R <- An,
        Now - maps:get({Name, Type}, Recent, Now - ?MIN_MULTICAST_INTERVAL_MS) >=
            ?MIN_MULTICAST_INTERVAL_MS
    ].

note_multicast(Keys, #state{recent_multicast = Recent0} = State) ->
    Now = erlang:monotonic_time(millisecond),
    Recent1 = lists:foldl(fun(Key, Acc) -> Acc#{Key => Now} end, Recent0, Keys),
    Recent =
        case map_size(Recent1) > ?RECENT_PRUNE_SIZE of
            true -> maps:filter(fun(_, T) -> Now - T < ?MIN_MULTICAST_INTERVAL_MS end, Recent1);
            false -> Recent1
        end,
    State#state{recent_multicast = Recent}.

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
    do_send_to(Rec, ?MDNS_GROUP, ?MDNS_PORT, State).

do_send_to(Rec, Ip, Port, State) ->
    Packet = inet_dns:encode(Rec, true),
    gen_udp:send(State#state.socket, Ip, Port, Packet).
