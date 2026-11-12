-module(mdns_app).

-moduledoc "OTP application callback module - starts the top-level supervisor.".

-behaviour(application).

-export([start/2, prep_stop/1, stop/1]).

start(_StartType, _StartArgs) ->
    mdns_sup:start_link().

%% Runs before the supervision tree is taken down, while every process
%% is still alive - the only point at which a goodbye (RFC 6762 10.1)
%% can still go out for each registered name: mdns_sup stops its
%% children in reverse start order, so by the time mdns_registry itself
%% terminates, mdns_socket is already gone. Without this, every name
%% this node published would linger in peers' caches for its full TTL
%% (4500s by default for a service's records) after the node stopped.
prep_stop(State) ->
    ok = mdns_registry:withdraw_all(),
    ok = mdns_socket:sync(),
    State.

stop(_State) ->
    ok.
