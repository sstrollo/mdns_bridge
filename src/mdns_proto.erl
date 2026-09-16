%%%-------------------------------------------------------------------
%% @doc Helpers for building/reading the #dns_rec{} terms that inet_dns
%% encodes/decodes, for both the mDNS side (Mdns=true) and the classic
%% unicast-DNS bridge side (Mdns=false).
%% @end
%%%-------------------------------------------------------------------
-module(mdns_proto).

-include("mdns_dns.hrl").

-export([
    normalize_name/1,
    mdns_query/2,
    extract_answers/1,
    dns_response/4
]).

-define(CLASS_IN, in).

%% DNS names are case-insensitive; normalize for use as cache keys.
-spec normalize_name(string() | binary()) -> string().
normalize_name(Name) when is_binary(Name) ->
    normalize_name(unicode:characters_to_list(Name));
normalize_name(Name) when is_list(Name) ->
    string:to_lower(strip_trailing_dot(Name)).

strip_trailing_dot(Name) ->
    case lists:reverse(Name) of
        [$. | Rest] -> lists:reverse(Rest);
        _ -> Name
    end.

%% Build an mDNS question packet (as a #dns_rec{}) asking for Type records
%% of Name. Plain (non-QU) question: we want the multicast answer, and it's
%% fine (and useful) if others on the link overhear it too.
-spec mdns_query(string(), atom()) -> #dns_rec{}.
mdns_query(Name, Type) ->
    Header = #dns_header{id = 0, qr = 0, opcode = 0, rd = 0},
    Query = #dns_query{
        domain = Name,
        type = Type,
        class = ?CLASS_IN,
        unicast_response = false
    },
    #dns_rec{header = Header, qdlist = [Query], anlist = [], nslist = [], arlist = []}.

%% Pull out {Name, Type, Data, Ttl, CacheFlush} tuples for every answer
%% (answer + additional section) we're prepared to cache: class IN only.
-spec extract_answers(#dns_rec{}) ->
    [{string(), atom(), term(), non_neg_integer(), boolean()}].
extract_answers(#dns_rec{anlist = An, arlist = Ar}) ->
    [
        {normalize_name(Domain), Type, Data, Ttl, CacheFlush}
     || #dns_rr{domain = Domain, type = Type, class = Class, data = Data,
                ttl = Ttl, func = CacheFlush} <- An ++ Ar,
        Class =:= ?CLASS_IN
    ].

%% Build a classic unicast-DNS response for the bridge server.
%% Answers :: [{Data, Ttl}] for the queried Name/Type.
-spec dns_response(#dns_rec{}, [{term(), non_neg_integer()}], atom(), boolean()) ->
    #dns_rec{}.
dns_response(#dns_rec{header = ReqHeader, qdlist = Qd}, Answers, Type, Found) ->
    Rcode =
        case {Found, Answers} of
            {true, _} -> 0;
            {false, []} -> 3; % NXDOMAIN
            {false, _} -> 0
        end,
    RespHeader = ReqHeader#dns_header{
        qr = 1,
        aa = 1,
        rd = ReqHeader#dns_header.rd,
        ra = 0,
        rcode = Rcode
    },
    AnList = [
        #dns_rr{domain = Domain, type = Type, class = ?CLASS_IN, ttl = Ttl, data = Data}
     || #dns_query{domain = Domain} <- Qd, {Data, Ttl} <- Answers
    ],
    #dns_rec{header = RespHeader, qdlist = Qd, anlist = AnList, nslist = [], arlist = []}.
