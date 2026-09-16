%%%-------------------------------------------------------------------
%% @doc Public API: register a `.local' name to announce over mDNS.
%%
%% By default this probes for a conflict first (RFC 6762 section 8)
%% before claiming the name, and keeps defending it for as long as it's
%% registered (RFC 6762 section 9) - see register/3's `probe` and
%% `on_conflict` options to change that.
%%
%% A registration is tied to the calling process - if it exits without
%% unregistering, the name is automatically withdrawn (a goodbye packet
%% is sent) so nothing outlives whatever wanted it published.
%% @end
%%%-------------------------------------------------------------------
-module(mdns).

-export([
    register/2,
    register/3,
    register_service/5,
    register_service/6,
    unregister/1,
    interface_changed/0
]).

%% @doc Equivalent to `register(Name, Ip, #{})'.
-spec register(string() | binary(), inet:ip4_address()) ->
    {ok, reference(), string()} | {error, term()}.
register(Name, Ip) ->
    mdns_registry:register(Name, Ip).

%% @doc Register Name (must end in `.local') to announce Ip over mDNS.
%%
%% By default Ip is required to be on the same subnet as the configured
%% mDNS interface, as a sanity check - pass `#{validate => false}' to
%% publish an address outside it anyway (e.g. one this host doesn't
%% itself own, being announced on another device's behalf).
%%
%% By default, probes for a conflict (RFC 6762 section 8) before
%% claiming the name - pass `#{probe => false}' to skip that and claim
%% it immediately instead, trusting the caller that it's unique.
%%
%% `on_conflict' controls what happens on a detected conflict, both at
%% probe time and later while the name is held (RFC 6762 section 9):
%%   - `error' (the default) - fail the registration / withdraw it.
%%   - `force' - claim/keep the name regardless of the conflict.
%%   - `{rename, Fun}' - probe time only: call `Fun(OriginalName, Attempt)'
%%     for a new name to try instead, up to the configured
%%     `max_rename_attempts' (default 10). `Fun' always receives the
%%     *original* name passed to register/2,3 (not the previous attempt's
%%     name) and the 1-based attempt number, and returns the next name to
%%     try - so a simple `fun(N, Attempt) -> N ++ "-" ++
%%     integer_to_list(Attempt) end' produces "foo-1", "foo-2", ... rather
%%     than compounding into "foo-1-2-3".
%%   - `auto' - shorthand for exactly that Fun (inserted before the
%%     `.local' suffix, so "foo.local" becomes "foo-1.local", not the
%%     invalid "foo.local-1").
%%
%% Returns `{ok, Ref, FinalName}' on success - `FinalName' is the name
%% actually claimed, which can differ from `Name' if `{rename, Fun}'
%% resolved a conflict. Keep `Ref' - it's what `unregister/1' takes, and
%% what a later `{mdns_bridge_conflict, Ref, FinalName}' message (sent to
%% the calling process if ongoing defense ever has to give up the name)
%% will reference.
%%
%% The registration is withdrawn automatically if the calling process
%% exits.
-spec register(string() | binary(), inet:ip4_address(), mdns_registry:opts()) ->
    {ok, reference(), string()} | {error, term()}.
register(Name, Ip, Opts) ->
    mdns_registry:register(Name, Ip, Opts).

%% @doc Equivalent to `register_service(InstanceName, ServiceType, Port,
%% TxtKVs, TargetHost, #{})'.
-spec register_service(
    string() | binary(),
    string() | binary(),
    non_neg_integer(),
    [{iodata(), iodata()} | iodata()],
    string() | binary()
) -> {ok, reference(), string()} | {error, term()}.
register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost) ->
    mdns_registry:register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost).

%% @doc Publish a DNS-SD (RFC 6763) service instance over mDNS: a
%% PTR + SRV + TXT record set, atomically, under one reference.
%%
%% `InstanceName' is free-form human-readable text (e.g. "My Printer") -
%% it does not need to be a valid DNS label itself, and is not required
%% to be unique across service types. `ServiceType' is
%% "_<app-protocol>._tcp" or "_<app-protocol>._udp" (e.g. "_http._tcp").
%% `Port' is the service's TCP/UDP port. `TxtKVs' is a list of
%% `{Key, Value}' pairs (encoded as `"Key=Value"') and/or plain
%% strings/binaries (a boolean-style key with no value); `[]' publishes
%% an empty TXT record.
%%
%% `TargetHost' is the `.local' hostname the service runs on - it does
%% *not* need to already be registered via register/2,3 (or be on this
%% node's subnet at all): any `.local' name is accepted, e.g. one owned
%% by another device entirely, or the same one this app already
%% publishes an A record for.
%%
%% Same `probe'/`on_conflict' options as register/3 (no `validate' -
%% there's no address here to sanity-check), applied to the service
%% *instance name*: with the default `probe => true', conflicts are
%% checked by probing the SRV and TXT records (sequentially, not as one
%% combined probe - see mdns_registry's module doc) before claiming
%% them; the PTR (service type -> instance) is never probed, since
%% multiple instances of one service type sharing that record is the
%% normal, expected case, not a conflict. For `on_conflict => auto' or
%% `{rename, Fun}', `Fun' operates on the plain instance name/label
%% (e.g. "My Printer"), not the full dotted DNS name.
%%
%% Returns `{ok, Ref, FinalInstanceName}' - `FinalInstanceName' is the
%% full `<instance>.<type>.local' name actually claimed. `Ref' behaves
%% exactly like register/3's: pass it to unregister/1, and it's what a
%% later `{mdns_bridge_conflict, Ref, FinalInstanceName}' message would
%% reference. Unregistering it withdraws the SRV, TXT, and this
%% instance's PTR together; the service-type-level meta-enumeration PTR
%% (`_services._dns-sd._udp.local') is reference-counted and only
%% withdrawn once no other live registration of the same `ServiceType'
%% remains.
-spec register_service(
    string() | binary(),
    string() | binary(),
    non_neg_integer(),
    [{iodata(), iodata()} | iodata()],
    string() | binary(),
    mdns_registry:service_opts()
) -> {ok, reference(), string()} | {error, term()}.
register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost, Opts) ->
    mdns_registry:register_service(InstanceName, ServiceType, Port, TxtKVs, TargetHost, Opts).

%% @doc Withdraw a name registered with register/2,3 or
%% register_service/5,6. Idempotent - a reference that's already gone
%% (unregistered, its owner already exited, or ongoing conflict defense
%% already gave it up) is not an error.
-spec unregister(reference()) -> ok.
unregister(Ref) ->
    mdns_registry:unregister(Ref).

%% @doc Call this when the embedding system detects that the configured
%% network interface's address (or netmask) changed - e.g. a DHCP
%% renewal, a link up/down event. This app does not watch for network
%% changes itself; detecting them is the embedder's job.
%%
%% Rejoins the mDNS multicast group on the new address if it changed,
%% and revalidates future registrations against the new subnet.
%% Existing registrations are left as they are - re-register anything
%% that should now be announced under a different address.
-spec interface_changed() -> ok | {error, term()}.
interface_changed() ->
    case mdns_socket:refresh_interface() of
        ok -> mdns_registry:refresh_interface();
        {error, _} = Err -> Err
    end.
