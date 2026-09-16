%%%-------------------------------------------------------------------
%% @doc Resolves the configured mDNS interface (a name like "eth0", or a
%% literal IPv4 address) to the IPv4 address to bind/join multicast on,
%% and to that interface's netmask (used by mdns_registry to sanity-check
%% addresses it's asked to publish).
%% @end
%%%-------------------------------------------------------------------
-module(mdns_iface).

-export([resolve/1, resolve_with_netmask/1, same_subnet/3]).

-type config() :: undefined | string() | binary() | inet:ip4_address().

-spec resolve(config()) -> {ok, inet:ip4_address()} | {error, term()}.
resolve(Config) ->
    case resolve_with_netmask(Config) of
        {ok, {Ip, _Netmask}} -> {ok, Ip};
        {error, _} = Err -> Err
    end.

-spec resolve_with_netmask(config()) ->
    {ok, {inet:ip4_address(), inet:ip4_address()}} | {error, term()}.
resolve_with_netmask(undefined) ->
    default_ipv4();
resolve_with_netmask({A, B, C, D} = Ip) when
    is_integer(A), is_integer(B), is_integer(C), is_integer(D)
->
    netmask_for_ip(Ip);
resolve_with_netmask(Name) when is_list(Name); is_binary(Name) ->
    IfName = unicode:characters_to_list(Name),
    case inet:parse_ipv4_address(IfName) of
        {ok, Ip} -> netmask_for_ip(Ip);
        {error, _} -> resolve_ifname(IfName)
    end.

%% Is Ip on the same subnet as (Base, Netmask)? Used to sanity-check
%% addresses mdns_registry is asked to publish against the configured
%% mDNS interface.
-spec same_subnet(inet:ip4_address(), inet:ip4_address(), inet:ip4_address()) -> boolean().
same_subnet({A1, B1, C1, D1}, {A2, B2, C2, D2}, {M1, M2, M3, M4}) ->
    (A1 band M1) =:= (A2 band M1) andalso
        (B1 band M2) =:= (B2 band M2) andalso
        (C1 band M3) =:= (C2 band M3) andalso
        (D1 band M4) =:= (D2 band M4).

resolve_ifname(IfName) ->
    case inet:getifaddrs() of
        {ok, IfAddrs} ->
            case lists:keyfind(IfName, 1, IfAddrs) of
                {IfName, Opts} -> first_ipv4_pair(ipv4_pairs(Opts), {error, no_ipv4_address});
                false -> {error, {no_such_interface, IfName}}
            end;
        {error, _} = Err ->
            Err
    end.

%% A literal IP was configured: find which local interface actually owns
%% it, so we can still report a real netmask instead of guessing one.
netmask_for_ip(Ip) ->
    case inet:getifaddrs() of
        {ok, IfAddrs} ->
            Pairs = lists:append([ipv4_pairs(Opts) || {_Name, Opts} <- IfAddrs]),
            case lists:keyfind(Ip, 1, Pairs) of
                {Ip, Mask} -> {ok, {Ip, Mask}};
                false -> {error, {interface_not_found_for_ip, Ip}}
            end;
        {error, _} = Err ->
            Err
    end.

first_ipv4_pair([Pair | _], _NotFound) -> {ok, Pair};
first_ipv4_pair([], NotFound) -> NotFound.

%% inet:getifaddrs/0 lists each address as {addr, Ip} immediately
%% followed by its {netmask, Mask} (optionally then {broadaddr, _}
%% before the next address) - pair them up, IPv4 only.
ipv4_pairs([{addr, Ip}, {netmask, Mask} | Rest]) when tuple_size(Ip) =:= 4 ->
    [{Ip, Mask} | ipv4_pairs(Rest)];
ipv4_pairs([_ | Rest]) ->
    ipv4_pairs(Rest);
ipv4_pairs([]) ->
    [].

%% No interface configured: pick the first "up", non-loopback interface
%% with an IPv4 address. Convenient for ad hoc/dev use; on a real
%% multi-homed host `interface` should be set explicitly.
default_ipv4() ->
    case inet:getifaddrs() of
        {ok, IfAddrs} ->
            Candidates = [
                Pair
             || {_Name, Opts} <- IfAddrs,
                Flags <- [proplists:get_value(flags, Opts, [])],
                lists:member(up, Flags),
                not lists:member(loopback, Flags),
                Pair <- ipv4_pairs(Opts)
            ],
            first_ipv4_pair(Candidates, {error, no_ipv4_interface});
        {error, _} = Err ->
            Err
    end.
