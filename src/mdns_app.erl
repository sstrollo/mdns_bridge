%%%-------------------------------------------------------------------
%% @doc mdns public API
%% @end
%%%-------------------------------------------------------------------

-module(mdns_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    mdns_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
