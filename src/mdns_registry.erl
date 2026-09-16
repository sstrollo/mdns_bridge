%%%-------------------------------------------------------------------
%% @doc Registry of names published via the mdns:register/2,3 API and
%% announced over mDNS. A registration is tied to the lifetime of the
%% calling process: if it dies without unregistering, we send a goodbye
%% (TTL=0) and clean up automatically.
%%
%% Deliberately out of scope for now (see the README): RFC 6762 probing
%% and conflict resolution. We trust the caller that a name is meant to
%% be unique and just announce it - a later addition of a conflict policy
%% (error | force | rename, say) is the natural extension point, not
%% something to half-build ahead of time.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_registry).

-behaviour(gen_server).

-export([
    child_spec/0,
    start_link/0,
    register/2,
    register/3,
    unregister/1,
    answers_for/2,
    refresh_interface/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export_type([opts/0]).

-define(SERVER, ?MODULE).
-define(TAB, mdns_registry_tab).
-define(DEFAULT_TTL, 120).
-define(REANNOUNCE_FOLLOWUP_MS, 1000).
-define(DEFAULT_REANNOUNCE_INTERVAL_MS, 60000).
-define(KNOWN_OPTS, [validate]).

-define(is_octet(X), (is_integer(X) andalso X >= 0 andalso X =< 255)).
-define(is_ipv4(Ip),
    (is_tuple(Ip) andalso
        tuple_size(Ip) =:= 4 andalso
        ?is_octet(element(1, Ip)) andalso
        ?is_octet(element(2, Ip)) andalso
        ?is_octet(element(3, Ip)) andalso
        ?is_octet(element(4, Ip)))
).

-record(state, {
    iface_ip :: inet:ip4_address(),
    netmask :: inet:ip4_address(),
    %% reference() -> {Name, Type, Data}, so a DOWN or explicit
    %% unregister can find what to withdraw.
    monitors = #{} :: #{reference() => {string(), atom(), term()}}
}).

-type opts() :: #{validate => boolean()}.

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec register(string() | binary(), inet:ip4_address()) ->
    {ok, reference()} | {error, term()}.
register(Name, Ip) ->
    register(Name, Ip, #{}).

-spec register(string() | binary(), inet:ip4_address(), opts()) ->
    {ok, reference()} | {error, term()}.
register(Name, Ip, Opts) when is_map(Opts) ->
    %% Validated here, in the caller's own process: a malformed Opts must
    %% never reach the gen_server as a bad message, since a crash there
    %% would take mdns_registry_tab (and every other caller's live
    %% registrations) down with it.
    case validate_opts(Opts) of
        ok -> gen_server:call(?SERVER, {register, mdns_proto:normalize_name(Name), Ip, Opts});
        {error, _} = Err -> Err
    end.

-spec unregister(reference()) -> ok.
unregister(Ref) ->
    gen_server:call(?SERVER, {unregister, Ref}).

%% Direct ETS read: current {Data, Ttl} answers for a published Name/Type.
-spec answers_for(string(), atom()) -> [{term(), non_neg_integer()}].
answers_for(Name, Type) ->
    [
        {Data, Ttl}
     || [Data, Ttl] <- ets:match(?TAB, {{Name, Type, '$1'}, #{ttl => '$2'}})
    ].

%% Call when the embedding system detects that the configured
%% interface's address or netmask changed (e.g. a DHCP renewal) - this
%% app does not watch for that itself. Revalidates future registrations
%% against the new subnet; existing registrations are unaffected.
-spec refresh_interface() -> ok | {error, term()}.
refresh_interface() ->
    gen_server:call(?SERVER, refresh_interface).

init([]) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve_with_netmask(IfaceConfig) of
        {ok, {IfaceIp, Netmask}} ->
            ets:new(?TAB, [set, public, named_table]),
            schedule_reannounce_all(),
            {ok, #state{iface_ip = IfaceIp, netmask = Netmask}};
        {error, Reason} ->
            {stop, {interface_resolve_failed, Reason}}
    end.

handle_call({register, Name, Ip, Opts}, {FromPid, _Tag}, State) ->
    case validate(Name, Ip, Opts, State) of
        ok ->
            {Ref, NewState} = do_register(Name, Ip, FromPid, State),
            {reply, {ok, Ref}, NewState};
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call({unregister, Ref}, _From, State) ->
    {reply, ok, withdraw(Ref, State)};
handle_call(refresh_interface, _From, State) ->
    IfaceConfig = application:get_env(mdns_bridge, interface, undefined),
    case mdns_iface:resolve_with_netmask(IfaceConfig) of
        {ok, {IfaceIp, Netmask}} ->
            {reply, ok, State#state{iface_ip = IfaceIp, netmask = Netmask}};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    {noreply, withdraw(Ref, State)};
handle_info({reannounce_one, Key}, State) ->
    reannounce(Key),
    {noreply, State};
handle_info(reannounce_all, State) ->
    [reannounce(Key) || {Key, _Entry} <- ets:tab2list(?TAB)],
    schedule_reannounce_all(),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- internal -------------------------------------------------------------

%% `validate` must be a boolean if present, and no unrecognized keys -
%% checked in the caller's own process (see register/3) so a malformed
%% Opts never reaches the gen_server as a message it might crash on.
validate_opts(Opts) ->
    case maps:keys(Opts) -- ?KNOWN_OPTS of
        [] ->
            case maps:get(validate, Opts, true) of
                B when is_boolean(B) -> ok;
                Other -> {error, {invalid_opts, #{validate => Other}}}
            end;
        Unknown ->
            {error, {invalid_opts, Unknown}}
    end.

validate(_Name, Ip, _Opts, _State) when not ?is_ipv4(Ip) ->
    {error, {invalid_address, Ip}};
validate(Name, Ip, Opts, State) ->
    case mdns_proto:is_local(Name) of
        false ->
            {error, {not_local, Name}};
        true ->
            case maps:get(validate, Opts, true) of
                false ->
                    ok;
                true ->
                    case mdns_iface:same_subnet(Ip, State#state.iface_ip, State#state.netmask) of
                        true -> ok;
                        false -> {error, {address_not_on_subnet, Ip}}
                    end;
                %% Defense in depth: register/3 already rejects this
                %% before it ever gets here, but never crash the
                %% gen_server (and thus every other caller's live
                %% registrations) over a malformed option.
                Other ->
                    {error, {invalid_opts, #{validate => Other}}}
            end
    end.

do_register(Name, Ip, FromPid, State) ->
    Key = {Name, a, Ip},
    Monitors0 = demonitor_previous_owner(Key, State#state.monitors),
    Ref = erlang:monitor(process, FromPid),
    Ttl = application:get_env(mdns_bridge, publish_ttl, ?DEFAULT_TTL),
    ets:insert(?TAB, {Key, #{ref => Ref, pid => FromPid, ttl => Ttl}}),
    mdns_socket:announce(Name, a, [{Ip, Ttl}]),
    erlang:send_after(?REANNOUNCE_FOLLOWUP_MS, self(), {reannounce_one, Key}),
    {Ref, State#state{monitors = Monitors0#{Ref => Key}}}.

demonitor_previous_owner(Key, Monitors) ->
    case ets:lookup(?TAB, Key) of
        [{Key, #{ref := OldRef}}] ->
            erlang:demonitor(OldRef, [flush]),
            maps:remove(OldRef, Monitors);
        [] ->
            Monitors
    end.

withdraw(Ref, State) ->
    case maps:take(Ref, State#state.monitors) of
        {Key, Monitors} ->
            erlang:demonitor(Ref, [flush]),
            maybe_delete_and_goodbye(Key, Ref),
            State#state{monitors = Monitors};
        error ->
            State
    end.

%% Only remove/goodbye if this Ref is still the current owner of Key - a
%% newer registration may have taken it over since (see
%% demonitor_previous_owner/2), in which case this Ref withdrawing must
%% not affect it.
maybe_delete_and_goodbye({Name, Type, Data} = Key, Ref) ->
    case ets:lookup(?TAB, Key) of
        [{Key, #{ref := Ref}}] ->
            ets:delete(?TAB, Key),
            mdns_socket:announce(Name, Type, [{Data, 0}]);
        _ ->
            ok
    end.

reannounce({Name, Type, Data} = Key) ->
    case ets:lookup(?TAB, Key) of
        [{Key, #{ttl := Ttl}}] -> mdns_socket:announce(Name, Type, [{Data, Ttl}]);
        [] -> ok
    end.

schedule_reannounce_all() ->
    Interval = application:get_env(
        mdns_bridge, publish_reannounce_ms, ?DEFAULT_REANNOUNCE_INTERVAL_MS
    ),
    erlang:send_after(Interval, self(), reannounce_all).
