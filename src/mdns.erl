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

-export([register/2, register/3, unregister/1, interface_changed/0]).

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

%% @doc Withdraw a name registered with register/2,3. Idempotent - a
%% reference that's already gone (unregistered, its owner already
%% exited, or ongoing conflict defense already gave it up) is not an
%% error.
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
