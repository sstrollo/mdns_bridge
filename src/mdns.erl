%%%-------------------------------------------------------------------
%% @doc Public API: register a `.local` name to announce over mDNS.
%%
%% A registration is tied to the calling process - if it exits without
%% unregistering, the name is automatically withdrawn (a goodbye packet
%% is sent) so nothing outlives whatever wanted it published.
%% @end
%%%-------------------------------------------------------------------
-module(mdns).

-export([register/2, register/3, unregister/1]).

%% @doc Equivalent to `register(Name, Ip, #{})'.
-spec register(string() | binary(), inet:ip4_address()) ->
    {ok, reference()} | {error, term()}.
register(Name, Ip) ->
    mdns_registry:register(Name, Ip).

%% @doc Register Name (must end in `.local') to announce Ip over mDNS.
%%
%% By default Ip is required to be on the same subnet as the configured
%% mDNS interface, as a sanity check - pass `#{validate => false}' to
%% publish an address outside it anyway (e.g. one this host doesn't
%% itself own, being announced on another device's behalf).
%%
%% Returns a reference to pass to unregister/1. The registration is also
%% withdrawn automatically if the calling process exits.
-spec register(string() | binary(), inet:ip4_address(), mdns_registry:opts()) ->
    {ok, reference()} | {error, term()}.
register(Name, Ip, Opts) ->
    mdns_registry:register(Name, Ip, Opts).

%% @doc Withdraw a name registered with register/2,3. Idempotent - a
%% reference that's already gone (unregistered, or its owner already
%% exited) is not an error.
-spec unregister(reference()) -> ok.
unregister(Ref) ->
    mdns_registry:unregister(Ref).
