-module(mdns_app).

-moduledoc "OTP application callback module - starts the top-level supervisor.".

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    mdns_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
