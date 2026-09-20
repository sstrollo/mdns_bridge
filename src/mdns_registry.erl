%%%-------------------------------------------------------------------
%% @doc Registry of names published via the mdns:register/2,3 (plain
%% hostnames) and mdns:register_service/5,6 (DNS-SD, RFC 6763) APIs, and
%% announced over mDNS. A registration is tied to the lifetime of the
%% calling process: if it dies without unregistering, we send a goodbye
%% (TTL=0) and clean up automatically.
%%
%% Implements RFC 6762 sections 8 and 9:
%%
%% - Probing (8.1): before claiming a name, register/2,3 and
%%   register_service/5,6 (in the calling process, not this gen_server -
%%   probing takes real time, at least ~750ms for three probes 250ms
%%   apart, and must not block every other registration attempt while it
%%   runs) send probe queries and listen for a conflicting answer or a
%%   competing simultaneous probe. A service registration probes its SRV
%%   and TXT records sequentially rather than as a single combined
%%   RFC 6762-recommended ANY-type probe - simpler, and since nothing is
%%   committed until both clear, still fully correct, just ~1.5s instead
%%   of ~750ms on the (presumably rarer) service-registration path.
%%   Simultaneous-probe tie-breaking (8.2, the lexicographic-comparison
%%   corner case for two hosts probing the identical name at the
%%   identical instant) is deliberately simplified to "treat it as a
%%   conflict" rather than implementing the full comparison - the case is
%%   rare, and a real comparison algorithm is a lot of surface area for it.
%% - Announcing (8.3): unchanged from before - an immediate announce, a
%%   follow-up ~1s later, then periodic keep-alives.
%% - Ongoing conflict defense (9): while a name is held, if some other
%%   host starts answering for it with different data (mdns_socket
%%   notifies us via notify_conflict/3), we reassert our own data once;
%%   if the same conflict recurs within ?DEFEND_GRACE_MS, we give up -
%%   withdraw every registration under that {Name, Type} (for a service,
%%   this means the whole service - SRV/TXT/PTR/meta-PTR contribution,
%%   not just whichever record type the conflict showed up on) and send
%%   each owning process `{mdns_bridge_conflict, Ref, Name}` - unless any
%%   of them registered with `on_conflict => force`, in which case we
%%   just keep defending forever. Conflict scope is {Name, Type} as a
%%   whole, not per individual registration, since this registry allows
%%   more than one registration to legitimately share a name
%%   (round-robin) and there's no way to tell "an external squatter" from
%%   "our own other registration" apart from data already being one of
%%   our own values.
%%
%% What a detected conflict (probe-time or ongoing) actually does is the
%% `on_conflict` option: `error` (fail/withdraw - the default), `force`
%% (claim/keep it regardless), `{rename, Fun}` (probe-time only: call
%% `Fun(OriginalName, Attempt)` for a new name and retry, up to
%% max_rename_attempts - always the *original* name, not the previous
%% attempt's, so a plain `Name ++ "-" ++ integer_to_list(Attempt)` Fun
%% produces "foo-1", "foo-2", ... rather than compounding into
%% "foo-1-2-3"; for a service, `Name` is the plain instance label, not
%% the full dotted name), or `auto` (shorthand for exactly that Fun).
%%
%% DNS-SD service registration publishes, atomically under one
%% reference: a SRV + TXT record at the instance name (RFC 6763 4.1,
%% probed/unique, like a host's A record), a PTR from the service type
%% name to the instance name (4.1, shared - never probed, multiple
%% instances of one type are the normal case), and increments a
%% reference count towards a PTR from `_services._dns-sd._udp.local` to
%% the service type name (9, the "what service types exist at all"
%% meta-enumeration record) - withdrawn only once nothing references
%% that service type anymore. The SRV target host does not need to have
%% been registered via mdns:register/2,3 itself - any `.local` name is
%% accepted.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_registry).

-behaviour(gen_server).

-export([
    child_spec/0,
    start_link/0,
    register/2,
    register/3,
    register_service/5,
    register_service/6,
    unregister/1,
    answers_for/2,
    notify_conflict/3,
    refresh_interface/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export_type([opts/0, service_opts/0]).

-define(SERVER, ?MODULE).
-define(TAB, mdns_registry_tab).
-define(DEFAULT_TTL, 120).
%% RFC 6763 recommends a much longer TTL for service records than for a
%% plain host's A record, since they change far less often.
-define(DEFAULT_SERVICE_TTL, 4500).
-define(REANNOUNCE_FOLLOWUP_MS, 1000).
-define(DEFAULT_REANNOUNCE_INTERVAL_MS, 60000).
-define(DEFAULT_MAX_RENAME_ATTEMPTS, 10).
-define(KNOWN_OPTS, [validate, probe, on_conflict]).
-define(KNOWN_SERVICE_OPTS, [probe, on_conflict]).
-define(META_SERVICE_NAME, "_services._dns-sd._udp.local").

%% RFC 6762 8.1: three probes, 250ms apart, preceded by a random 0-249ms
%% delay (spreads out synchronized probing after e.g. a mass power-on).
-define(PROBE_COUNT, 3).
-define(PROBE_INTERVAL_MS, 250).
%% RFC 6762 section 9 doesn't mandate an exact figure for how soon a
%% repeat conflict counts as "persistent" rather than transient; 10s
%% comfortably separates one stray packet from a real, sustained conflict.
-define(DEFEND_GRACE_MS, 10000).

-define(is_octet(X), (is_integer(X) andalso X >= 0 andalso X =< 255)).
-define(is_ipv4(Ip),
    (is_tuple(Ip) andalso
        tuple_size(Ip) =:= 4 andalso
        ?is_octet(element(1, Ip)) andalso
        ?is_octet(element(2, Ip)) andalso
        ?is_octet(element(3, Ip)) andalso
        ?is_octet(element(4, Ip)))
).
-define(is_port_number(P), (is_integer(P) andalso P >= 0 andalso P =< 65535)).

-type key() :: {string(), atom(), term()}.
%% reference() -> what to withdraw when this registration goes away:
%% a plain host (one key) or a service (several keys sharing one
%% reference count contribution towards the meta-enumeration PTR).
-type registration() ::
    {host, key(), pid()}
    | {service, [key()], ServiceTypeName :: string(), pid()}.

-record(state, {
    iface_ip :: inet:ip4_address(),
    netmask :: inet:ip4_address(),
    monitors = #{} :: #{reference() => registration()},
    %% {Name, Type} -> monotonic ms of the last time we defended it -
    %% RFC 6762 section 9 ongoing conflict defense.
    defenses = #{} :: #{{string(), atom()} => integer()},
    %% ServiceTypeName -> count of live service registrations of that
    %% type, so the shared meta-enumeration PTR is only withdrawn once
    %% nothing references it anymore.
    meta_ptr_refs = #{} :: #{string() => pos_integer()}
}).

-type on_conflict() ::
    error
    | force
    | auto
    | {rename, fun((string(), pos_integer()) -> string() | binary())}.
-type opts() :: #{validate => boolean(), probe => boolean(), on_conflict => on_conflict()}.
-type service_opts() :: #{probe => boolean(), on_conflict => on_conflict()}.

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec register(string() | binary(), inet:ip4_address()) ->
    {ok, reference(), string()} | {error, term()}.
register(Name, Ip) ->
    register(Name, Ip, #{}).

-spec register(string() | binary(), inet:ip4_address(), opts()) ->
    {ok, reference(), string()} | {error, term()}.
register(Name, Ip, Opts) when is_map(Opts) ->
    %% Validated here, in the caller's own process: a malformed Opts must
    %% never reach the gen_server as a bad message, since a crash there
    %% would take mdns_registry_tab (and every other caller's live
    %% registrations) down with it.
    case validate_opts(Opts, ?KNOWN_OPTS, [validate, probe]) of
        ok ->
            NormName = mdns_proto:normalize_name(Name),
            attempt_register(NormName, NormName, Ip, Opts, 1);
        {error, _} = Err ->
            Err
    end.

-spec register_service(
    string() | binary(),
    string() | binary(),
    non_neg_integer(),
    [{iodata(), iodata()} | iodata()],
    string() | binary()
) -> {ok, reference(), string()} | {error, term()}.
register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost) ->
    register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost, #{}).

-spec register_service(
    string() | binary(),
    string() | binary(),
    non_neg_integer(),
    [{iodata(), iodata()} | iodata()],
    string() | binary(),
    service_opts()
) -> {ok, reference(), string()} | {error, term()}.
register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost, Opts) when is_map(Opts) ->
    case validate_opts(Opts, ?KNOWN_SERVICE_OPTS, [probe]) of
        {error, _} = Err ->
            Err;
        ok ->
            case validate_service_args(ServiceType, Port, TargetHost) of
                {error, _} = Err ->
                    Err;
                ok ->
                    Ctx = #{
                        service_type => ServiceType,
                        service_type_name => mdns_proto:service_type_name(ServiceType),
                        port => Port,
                        txt => mdns_proto:build_txt_data(TxtKVs),
                        target => mdns_proto:normalize_name(TargetHost),
                        opts => Opts
                    },
                    attempt_register_service(InstanceName, Ctx, 1)
            end
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

%% mdns_socket calls this (RFC 6762 section 9) when it sees an answer for
%% Name/Type whose Data doesn't match any of our own current values.
-spec notify_conflict(string(), atom(), term()) -> ok.
notify_conflict(Name, Type, Data) ->
    gen_server:cast(?SERVER, {conflict, Name, Type, Data}).

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

handle_call({precheck, Name, Ip, Opts}, _From, State) ->
    {reply, validate(Name, Ip, Opts, State), State};
handle_call({commit, Name, Ip, Opts}, {FromPid, _Tag}, State) ->
    case validate(Name, Ip, Opts, State) of
        ok ->
            {Ref, NewState} = do_register(Name, Ip, Opts, FromPid, State),
            {reply, {ok, Ref}, NewState};
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call(
    {commit_service, InstanceFullName, ServiceTypeName, Port, Target, TxtData, Opts},
    {FromPid, _Tag},
    State
) ->
    {Ref, NewState} = do_register_service(
        InstanceFullName, ServiceTypeName, Port, Target, TxtData, Opts, FromPid, State
    ),
    {reply, {ok, Ref}, NewState};
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

handle_cast({conflict, Name, Type, Data}, State) ->
    {noreply, handle_ongoing_conflict(Name, Type, Data, State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    {noreply, withdraw(Ref, State)};
handle_info({reannounce_one, Key}, State) ->
    reannounce(Key),
    {noreply, State};
handle_info(reannounce_all, State) ->
    ets:foldl(
        fun({Key, _Entry}, ok) ->
            reannounce(Key),
            ok
        end,
        ok,
        ?TAB
    ),
    schedule_reannounce_all(),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

%% -- register/2,3's probing + rename loop (runs in the caller's process) --

attempt_register(OriginalName, CandidateName, Ip, Opts, Attempt) ->
    case gen_server:call(?SERVER, {precheck, CandidateName, Ip, Opts}) of
        {error, _} = Err ->
            Err;
        ok ->
            case maps:get(probe, Opts, true) of
                false ->
                    commit(CandidateName, Ip, Opts);
                true ->
                    Ttl = application:get_env(mdns_bridge, publish_ttl, ?DEFAULT_TTL),
                    case probe(CandidateName, a, Ip, Ttl) of
                        no_conflict ->
                            commit(CandidateName, Ip, Opts);
                        {conflict, Reason} ->
                            resolve_conflict_policy(
                                OriginalName,
                                CandidateName,
                                Opts,
                                Attempt,
                                Reason,
                                fun() -> commit(CandidateName, Ip, Opts) end,
                                fun(NewName, NextAttempt) ->
                                    attempt_register(OriginalName, NewName, Ip, Opts, NextAttempt)
                                end
                            )
                    end
            end
    end.

commit(Name, Ip, Opts) ->
    case gen_server:call(?SERVER, {commit, Name, Ip, Opts}) of
        {ok, Ref} -> {ok, Ref, Name};
        {error, _} = Err -> Err
    end.

%% -- register_service/5,6's probing + rename loop --------------------------

attempt_register_service(InstanceLabel, Ctx, Attempt) ->
    #{service_type := ServiceType, opts := Opts} = Ctx,
    InstanceFullName = mdns_proto:service_instance_name(InstanceLabel, ServiceType),
    case maps:get(probe, Opts, true) of
        false ->
            commit_service(InstanceFullName, Ctx);
        true ->
            case probe_service(InstanceFullName, Ctx) of
                no_conflict ->
                    commit_service(InstanceFullName, Ctx);
                {conflict, Reason} ->
                    resolve_conflict_policy(
                        InstanceLabel,
                        InstanceFullName,
                        Opts,
                        Attempt,
                        Reason,
                        fun() -> commit_service(InstanceFullName, Ctx) end,
                        fun(NewLabel, NextAttempt) ->
                            attempt_register_service(NewLabel, Ctx, NextAttempt)
                        end
                    )
            end
    end.

%% Sequentially probes SRV then TXT for InstanceFullName - see the
%% moduledoc for why this is sequential rather than one combined
%% RFC 6762-recommended ANY-type probe. Nothing is committed until both
%% clear, so this is fully correct either way.
probe_service(InstanceFullName, Ctx) ->
    #{port := Port, target := Target, txt := TxtData} = Ctx,
    Ttl = application:get_env(mdns_bridge, service_ttl, ?DEFAULT_SERVICE_TTL),
    SrvData = {0, 0, Port, Target},
    case probe(InstanceFullName, srv, SrvData, Ttl) of
        no_conflict ->
            case probe(InstanceFullName, txt, TxtData, Ttl) of
                no_conflict -> no_conflict;
                {conflict, OtherData} -> {conflict, {txt, OtherData}}
            end;
        {conflict, OtherData} ->
            {conflict, {srv, OtherData}}
    end.

commit_service(InstanceFullName, Ctx) ->
    #{
        service_type_name := ServiceTypeName,
        port := Port,
        target := Target,
        txt := TxtData,
        opts := Opts
    } = Ctx,
    Call = {commit_service, InstanceFullName, ServiceTypeName, Port, Target, TxtData, Opts},
    case gen_server:call(?SERVER, Call) of
        {ok, Ref} -> {ok, Ref, InstanceFullName};
        {error, _} = Err -> Err
    end.

%% -- shared conflict-policy handling (used by both register flows) --------

%% CommitFun/0 claims CandidateName as-is (force); RetryFun/2 restarts
%% the whole attempt under a renamed candidate. Always renames from
%% OriginalName (the plain label, not the previous attempt's derived
%% name) - see the moduledoc.
resolve_conflict_policy(OriginalName, CandidateName, Opts, Attempt, Reason, CommitFun, RetryFun) ->
    case resolve_on_conflict(maps:get(on_conflict, Opts, error)) of
        error ->
            {error, {name_conflict, CandidateName, Reason}};
        force ->
            CommitFun();
        {rename, Fun} ->
            MaxAttempts = application:get_env(
                mdns_bridge, max_rename_attempts, ?DEFAULT_MAX_RENAME_ATTEMPTS
            ),
            case Attempt < MaxAttempts of
                true ->
                    case rename_via(Fun, OriginalName, Attempt) of
                        {ok, NewName} -> RetryFun(NewName, Attempt + 1);
                        {error, _} = Err -> Err
                    end;
                false ->
                    {error, {name_conflict, CandidateName, Reason}}
            end
    end.

%% `auto` is shorthand for the rename scheme documented in the README:
%% append "-Attempt" to the name - before the `.local` suffix, not after
%% it, since "foo.local-1" isn't a `.local` name at all and would just
%% fail the next precheck. For a service registration, Name here is the
%% plain instance label (no `.local` suffix to begin with), so this
%% degrades to a plain append - see split_local_suffix/1.
resolve_on_conflict(auto) -> {rename, fun default_rename_fun/2};
resolve_on_conflict(OnConflict) -> OnConflict.

default_rename_fun(Name, Attempt) ->
    {Base, Suffix} = split_local_suffix(Name),
    Base ++ "-" ++ integer_to_list(Attempt) ++ Suffix.

split_local_suffix(Name) ->
    case lists:suffix(".local", Name) of
        true -> {lists:sublist(Name, length(Name) - length(".local")), ".local"};
        false -> {Name, ""}
    end.

rename_via(Fun, Name, Attempt) ->
    try Fun(Name, Attempt) of
        NewName when is_list(NewName); is_binary(NewName) ->
            {ok, mdns_proto:normalize_name(NewName)};
        Other ->
            {error, {rename_fun_failed, {invalid_return, Other}}}
    catch
        Class:Reason ->
            {error, {rename_fun_failed, {Class, Reason}}}
    end.

%% RFC 6762 8.1: probe, then wait for a conflicting answer or a competing
%% simultaneous probe. Blocks the calling process for
%% ?PROBE_COUNT * ?PROBE_INTERVAL_MS (plus jitter) in the no-conflict case.
probe(Name, Type, Data, Ttl) ->
    mdns_socket:probe_subscribe(Name, Type),
    timer:sleep(rand:uniform(?PROBE_INTERVAL_MS) - 1),
    Result = probe_rounds(Name, Type, Data, Ttl, ?PROBE_COUNT),
    mdns_socket:probe_unsubscribe(Name, Type),
    flush_probe_messages(Name, Type),
    Result.

probe_rounds(_Name, _Type, _Data, _Ttl, 0) ->
    no_conflict;
probe_rounds(Name, Type, Data, Ttl, Remaining) ->
    mdns_socket:send_probe(Name, Type, Data, Ttl),
    case await_probe_conflict(Name, Type, Data, ?PROBE_INTERVAL_MS) of
        no_conflict -> probe_rounds(Name, Type, Data, Ttl, Remaining - 1);
        {conflict, _} = Conflict -> Conflict
    end.

await_probe_conflict(Name, Type, Data, TimeoutMs) ->
    receive
        {mdns_probe_seen, Name, Type, OtherData} when OtherData =/= Data ->
            {conflict, OtherData}
    after TimeoutMs ->
        no_conflict
    end.

flush_probe_messages(Name, Type) ->
    receive
        {mdns_probe_seen, Name, Type, _} -> flush_probe_messages(Name, Type)
    after 0 ->
        ok
    end.

%% -- internal -------------------------------------------------------------

%% `validate`/`probe` (whichever of the two are in BoolKeys - register/2,3
%% checks both, register_service/5,6 only has `probe`) must be booleans
%% if present; `on_conflict` must be `error`, `force`, `auto`, or
%% `{rename, Fun}` with Fun a 2-arity fun; no unrecognized keys.
validate_opts(Opts, KnownKeys, BoolKeys) ->
    case maps:keys(Opts) -- KnownKeys of
        [] -> validate_opt_values(Opts, BoolKeys);
        Unknown -> {error, {invalid_opts, Unknown}}
    end.

validate_opt_values(Opts, BoolKeys) ->
    case lists:all(fun(Key) -> is_valid_bool_opt(Key, Opts) end, BoolKeys) of
        false ->
            {error, {invalid_opts, bad_boolean_option}};
        true ->
            case maps:find(on_conflict, Opts) of
                error -> ok;
                {ok, OnConflict} -> validate_on_conflict(OnConflict)
            end
    end.

is_valid_bool_opt(Key, Opts) ->
    case maps:get(Key, Opts, true) of
        B when is_boolean(B) -> true;
        _ -> false
    end.

validate_on_conflict(error) -> ok;
validate_on_conflict(force) -> ok;
validate_on_conflict(auto) -> ok;
validate_on_conflict({rename, Fun}) when is_function(Fun, 2) -> ok;
validate_on_conflict(Other) -> {error, {invalid_opts, #{on_conflict => Other}}}.

validate(_Name, Ip, _Opts, _State) when not ?is_ipv4(Ip) ->
    {error, {invalid_address, Ip}};
validate(Name, Ip, Opts, State) ->
    case mdns_proto:is_local(Name) of
        false ->
            {error, {not_local, Name}};
        true ->
            case maps:get(validate, Opts, true) of
                false -> ok;
                true -> validate_subnet(Ip, State)
            end
    end.

validate_subnet(Ip, State) ->
    case mdns_iface:same_subnet(Ip, State#state.iface_ip, State#state.netmask) of
        true -> ok;
        false -> {error, {address_not_on_subnet, Ip}}
    end.

%% ServiceType must look like "_app._tcp"/"_app._udp"; Port must be a
%% real port number; TargetHost must be a `.local` name (not required to
%% be one this app itself has registered).
validate_service_args(ServiceType, Port, TargetHost) ->
    case is_valid_service_type(ServiceType) of
        false ->
            {error, {invalid_service_type, ServiceType}};
        true ->
            case ?is_port_number(Port) of
                false -> {error, {invalid_port, Port}};
                true -> validate_target_host(TargetHost)
            end
    end.

validate_target_host(TargetHost) ->
    case mdns_proto:is_local(mdns_proto:normalize_name(TargetHost)) of
        true -> ok;
        false -> {error, {not_local, TargetHost}}
    end.

is_valid_service_type(ServiceType) ->
    case split_service_type(ServiceType) of
        {ok, App, Proto} ->
            lists:prefix("_", App) andalso
                length(App) > 1 andalso
                (Proto =:= "_tcp" orelse Proto =:= "_udp");
        error ->
            false
    end.

split_service_type(ServiceType) when is_binary(ServiceType) ->
    split_service_type(unicode:characters_to_list(ServiceType));
split_service_type(ServiceType) when is_list(ServiceType) ->
    case string:split(ServiceType, ".") of
        [App, Proto] when App =/= [] -> {ok, App, Proto};
        _ -> error
    end;
split_service_type(_) ->
    error.

do_register(Name, Ip, Opts, FromPid, State) ->
    Key = {Name, a, Ip},
    Monitors0 = demonitor_previous_owner(Key, State#state.monitors),
    Ref = erlang:monitor(process, FromPid),
    Ttl = application:get_env(mdns_bridge, publish_ttl, ?DEFAULT_TTL),
    OnConflict = maps:get(on_conflict, Opts, error),
    ets:insert(?TAB, {Key, #{ref => Ref, pid => FromPid, ttl => Ttl, on_conflict => OnConflict}}),
    mdns_socket:announce(Name, a, [{Ip, Ttl}]),
    erlang:send_after(?REANNOUNCE_FOLLOWUP_MS, self(), {reannounce_one, Key}),
    {Ref, State#state{monitors = Monitors0#{Ref => {host, Key, FromPid}}}}.

do_register_service(InstanceFullName, ServiceTypeName, Port, Target, TxtData, Opts, FromPid, State) ->
    Ttl = application:get_env(mdns_bridge, service_ttl, ?DEFAULT_SERVICE_TTL),
    SrvKey = {InstanceFullName, srv, {0, 0, Port, Target}},
    TxtKey = {InstanceFullName, txt, TxtData},
    PtrKey = {ServiceTypeName, ptr, InstanceFullName},
    OnConflict = maps:get(on_conflict, Opts, error),
    Monitors0 = demonitor_previous_owner(SrvKey, State#state.monitors),
    Monitors1 = demonitor_previous_owner(TxtKey, Monitors0),
    Monitors2 = demonitor_previous_owner(PtrKey, Monitors1),
    Ref = erlang:monitor(process, FromPid),
    RowValue = #{ref => Ref, pid => FromPid, ttl => Ttl, on_conflict => OnConflict},
    ets:insert(?TAB, [{SrvKey, RowValue}, {TxtKey, RowValue}, {PtrKey, RowValue}]),
    mdns_socket:announce(InstanceFullName, srv, [{{0, 0, Port, Target}, Ttl}]),
    mdns_socket:announce(InstanceFullName, txt, [{TxtData, Ttl}]),
    mdns_socket:announce(ServiceTypeName, ptr, [{InstanceFullName, Ttl}]),
    erlang:send_after(?REANNOUNCE_FOLLOWUP_MS, self(), {reannounce_one, SrvKey}),
    erlang:send_after(?REANNOUNCE_FOLLOWUP_MS, self(), {reannounce_one, TxtKey}),
    erlang:send_after(?REANNOUNCE_FOLLOWUP_MS, self(), {reannounce_one, PtrKey}),
    {MetaRefs, ShouldAnnounceMeta} = bump_meta_ptr(ServiceTypeName, State#state.meta_ptr_refs),
    ShouldAnnounceMeta andalso
        begin
            ets:insert(?TAB, {{?META_SERVICE_NAME, ptr, ServiceTypeName}, #{ttl => Ttl}}),
            mdns_socket:announce(?META_SERVICE_NAME, ptr, [{ServiceTypeName, Ttl}])
        end,
    NewMonitors = Monitors2#{Ref => {service, [SrvKey, TxtKey, PtrKey], ServiceTypeName, FromPid}},
    {Ref, State#state{monitors = NewMonitors, meta_ptr_refs = MetaRefs}}.

bump_meta_ptr(ServiceTypeName, Refs) ->
    Count = maps:get(ServiceTypeName, Refs, 0),
    {Refs#{ServiceTypeName => Count + 1}, Count =:= 0}.

release_meta_ptr(ServiceTypeName, Refs) ->
    case maps:get(ServiceTypeName, Refs, 0) of
        Count when Count =< 1 -> {maps:remove(ServiceTypeName, Refs), true};
        Count -> {Refs#{ServiceTypeName => Count - 1}, false}
    end.

demonitor_previous_owner(Key, Monitors) ->
    case ets:lookup(?TAB, Key) of
        [{Key, #{ref := OldRef}}] ->
            erlang:demonitor(OldRef, [flush]),
            maps:remove(OldRef, Monitors);
        [] ->
            Monitors
    end.

%% Withdraws whatever Ref refers to (host or service) - used for an
%% explicit unregister/1 and a DOWN. No owner notification: the caller
%% either asked for this, or is already dead. Ongoing conflict defense
%% giving up uses withdraw_due_to_conflict/2 instead, which does notify.
withdraw(Ref, State) ->
    do_withdraw(Ref, State, false).

withdraw_due_to_conflict(Ref, State) ->
    do_withdraw(Ref, State, true).

do_withdraw(Ref, State, Notify) ->
    case maps:take(Ref, State#state.monitors) of
        {Registration, Monitors} ->
            erlang:demonitor(Ref, [flush]),
            withdraw_registration(Ref, Registration, Notify, State#state{monitors = Monitors});
        error ->
            State
    end.

withdraw_registration(Ref, {host, {Name, _Type, _Data} = Key, Pid}, Notify, State) ->
    maybe_delete_and_goodbye(Key, Ref),
    Notify andalso (Pid ! {mdns_bridge_conflict, Ref, Name}),
    State;
withdraw_registration(Ref, {service, Keys, ServiceType, Pid}, Notify, State) ->
    [maybe_delete_and_goodbye(Key, Ref) || Key <- Keys],
    [{InstanceName, _, _} | _] = Keys,
    Notify andalso (Pid ! {mdns_bridge_conflict, Ref, InstanceName}),
    {NewMetaRefs, ShouldGoodbye} = release_meta_ptr(ServiceType, State#state.meta_ptr_refs),
    ShouldGoodbye andalso
        begin
            ets:delete(?TAB, {?META_SERVICE_NAME, ptr, ServiceType}),
            mdns_socket:announce(?META_SERVICE_NAME, ptr, [{ServiceType, 0}])
        end,
    State#state{meta_ptr_refs = NewMetaRefs}.

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

%% -- RFC 6762 section 9: ongoing conflict defense --------------------------

handle_ongoing_conflict(Name, Type, Data, State) ->
    Rows = ets:match_object(?TAB, {{Name, Type, '_'}, '_'}),
    OurData = [D || {{_, _, D}, _} <- Rows],
    case Rows =:= [] orelse lists:member(Data, OurData) of
        true ->
            %% Nothing registered here anymore, or it's one of our own
            %% (e.g. a legitimate round-robin sibling registration) - not
            %% a conflict.
            State;
        false ->
            resolve_conflict(Name, Type, Rows, State)
    end.

resolve_conflict(Name, Type, Rows, State) ->
    case any_force(Rows) of
        true ->
            defend(Name, Type, Rows, State);
        false ->
            Now = erlang:monotonic_time(millisecond),
            case maps:get({Name, Type}, State#state.defenses, undefined) of
                LastDefended when
                    is_integer(LastDefended), Now - LastDefended < ?DEFEND_GRACE_MS
                ->
                    give_up(Name, Type, Rows, State);
                _ ->
                    defend(Name, Type, Rows, State)
            end
    end.

any_force(Rows) ->
    lists:any(
        fun
            ({_Key, #{on_conflict := force}}) -> true;
            (_) -> false
        end,
        Rows
    ).

defend(Name, Type, Rows, State) ->
    Answers = [{Data, maps:get(ttl, Value)} || {{_, _, Data}, Value} <- Rows],
    mdns_socket:announce(Name, Type, Answers),
    Now = erlang:monotonic_time(millisecond),
    State#state{defenses = (State#state.defenses)#{{Name, Type} => Now}}.

%% Withdraws every *registration* touching Rows (not just the rows
%% themselves) - so if one of them is a service's SRV row, the whole
%% service (SRV/TXT/PTR/meta-PTR) goes with it, rather than orphaning
%% the rest of it.
give_up(Name, Type, Rows, State) ->
    Refs = lists:usort([Ref || {_Key, #{ref := Ref}} <- Rows]),
    NewState = lists:foldl(
        fun(Ref, AccState) -> withdraw_due_to_conflict(Ref, AccState) end, State, Refs
    ),
    NewState#state{defenses = maps:remove({Name, Type}, NewState#state.defenses)}.
