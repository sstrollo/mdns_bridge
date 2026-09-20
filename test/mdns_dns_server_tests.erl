-module(mdns_dns_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_dns.hrl").

%% Non-.local queries must come back NOERROR/empty, never REFUSED:
%% inet_res's nameservers -> alt_nameservers fallback only triggers on
%% NXDOMAIN or an empty-but-OK answer, never on REFUSED. See the README's
%% inet_db section and mdns_dns_server's module doc.
non_local_query_is_empty_noerror_test() ->
    Req = request("example.com", a),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

%% A record type this bridge doesn't understand (unlike a/ptr/srv/txt) -
%% must not even try to resolve it, just fall through to empty NOERROR.
unsupported_type_local_query_is_empty_noerror_test() ->
    Req = request("widget.local", mx),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

request(Name, Type) ->
    #dns_rec{
        header = #dns_header{id = 7, rd = true},
        qdlist = [#dns_query{domain = Name, type = Type, class = in}]
    }.

should_accept_test_() ->
    [
        ?_assert(mdns_dns_server:should_accept(infinity, 999999999)),
        ?_assert(mdns_dns_server:should_accept(5, 0)),
        ?_assert(mdns_dns_server:should_accept(5, 4)),
        ?_assertNot(mdns_dns_server:should_accept(5, 5)),
        ?_assertNot(mdns_dns_server:should_accept(5, 6))
    ].

%% Beyond `a`, the bridge must resolve ptr/srv/txt too (DNS-SD) - via the
%% same mdns_query:resolve/3 path, which checks mdns_registry then falls
%% back to mdns_cache. No mdns_socket needed: nothing here is registered,
%% so mdns_query never reaches its on-demand-query fallback.
supported_types_test_() ->
    {setup, fun start/0, fun stop/1, fun(_) ->
        [
            fun resolves_ptr_from_cache/0,
            fun resolves_srv_from_cache/0,
            fun resolves_txt_from_cache/0
        ]
    end}.

start() ->
    {ok, CachePid} = mdns_cache:start_link(),
    {ok, RegistryPid} = mdns_registry:start_link(),
    [CachePid, RegistryPid].

stop(Pids) ->
    [gen_server:stop(Pid) || Pid <- lists:reverse(Pids)].

%% Cache entries here use the same shapes mdns_proto:extract_records/1
%% would actually produce from real traffic: binary Name, and (via
%% from_wire_data/2) binary PTR/SRV domain-shaped data too - see
%% mdns_proto's moduledoc. dns_response/4 converts PTR/SRV data back to
%% a wire-shaped list via to_wire_data/2 before it reaches the response
%% record, so those two assertions stay list literals; TXT isn't
%% converted on the way out (inet_dns accepts binaries for TXT directly
%% at encode time), so that one stays binary.
resolves_ptr_from_cache() ->
    ok = mdns_cache:insert_many([
        {~"_http._tcp.local", ptr, ~"My Printer._http._tcp.local", 4500, false}
    ]),
    Req = request("_http._tcp.local", ptr),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch(
        [#dns_rr{domain = "_http._tcp.local", type = ptr, data = "My Printer._http._tcp.local"}],
        Resp#dns_rec.anlist
    ).

resolves_srv_from_cache() ->
    ok = mdns_cache:insert_many([
        {~"my-printer._http._tcp.local", srv, {0, 0, 631, ~"printerhost.local"}, 120, false}
    ]),
    Req = request("my-printer._http._tcp.local", srv),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch(
        [#dns_rr{type = srv, data = {0, 0, 631, "printerhost.local"}}],
        Resp#dns_rec.anlist
    ).

resolves_txt_from_cache() ->
    ok = mdns_cache:insert_many([
        {~"my-printer._http._tcp.local", txt, [~"path=/"], 120, false}
    ]),
    Req = request("my-printer._http._tcp.local", txt),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch([#dns_rr{type = txt, data = [~"path=/"]}], Resp#dns_rec.anlist).
