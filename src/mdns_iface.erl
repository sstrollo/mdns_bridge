%%%-------------------------------------------------------------------
%% @doc Resolves the configured mDNS interface (a name like "eth0", or a
%% literal IPv4 address) to the IPv4 address to bind/join multicast on.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_iface).

-export([resolve/1]).

-spec resolve(undefined | string() | binary() | inet:ip4_address()) ->
    {ok, inet:ip4_address()} | {error, term()}.
resolve(undefined) ->
    default_ipv4();
resolve({A, B, C, D} = Ip)
  when is_integer(A), is_integer(B), is_integer(C), is_integer(D) ->
    {ok, Ip};
resolve(Name) when is_list(Name); is_binary(Name) ->
    IfName = unicode:characters_to_list(Name),
    case inet:parse_ipv4_address(IfName) of
        {ok, Ip} ->
            {ok, Ip};
        {error, _} ->
            resolve_ifname(IfName)
    end.

resolve_ifname(IfName) ->
    case inet:getifaddrs() of
        {ok, IfAddrs} ->
            case lists:keyfind(IfName, 1, IfAddrs) of
                {IfName, Opts} -> find_ipv4(Opts);
                false -> {error, {no_such_interface, IfName}}
            end;
        {error, _} = Err ->
            Err
    end.

find_ipv4(Opts) ->
    case [Addr || {addr, Addr} <- Opts, tuple_size(Addr) =:= 4] of
        [Ip | _] -> {ok, Ip};
        [] -> {error, no_ipv4_address}
    end.

%% No interface configured: pick the first "up", non-loopback interface
%% with an IPv4 address. Convenient for ad hoc/dev use; on a real
%% multi-homed host `interface` should be set explicitly.
default_ipv4() ->
    case inet:getifaddrs() of
        {ok, IfAddrs} ->
            Candidates = [
                Ip
             || {_Name, Opts} <- IfAddrs,
                Flags <- [proplists:get_value(flags, Opts, [])],
                lists:member(up, Flags),
                not lists:member(loopback, Flags),
                {ok, Ip} <- [find_ipv4(Opts)]
            ],
            case Candidates of
                [Ip | _] -> {ok, Ip};
                [] -> {error, no_ipv4_interface}
            end;
        {error, _} = Err ->
            Err
    end.
