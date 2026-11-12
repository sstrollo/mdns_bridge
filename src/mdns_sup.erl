-module(mdns_sup).

-moduledoc "Top-level supervisor.".

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% The children form a dependency chain, in this order: mdns_socket reads
%% mdns_cache's and mdns_registry's ETS tables and calls mdns_cache for
%% every packet it receives; mdns_query and mdns_dns_server depend on all
%% three. An ETS table dies with its owner, so if mdns_cache or
%% mdns_registry restarts, everything after it in the chain has to
%% restart too rather than keep failing against a table that no longer
%% exists - which is exactly what rest_for_one does. (A restart of a
%% later child, e.g. mdns_socket, leaves the earlier ones - and every
%% live registration - alone.)
init([]) ->
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 5,
        period => 10
    },
    ChildSpecs = [
        mdns_cache:child_spec(),
        mdns_registry:child_spec(),
        mdns_socket:child_spec(),
        mdns_query:child_spec(),
        mdns_dns_server:child_spec()
    ],
    {ok, {SupFlags, ChildSpecs}}.
