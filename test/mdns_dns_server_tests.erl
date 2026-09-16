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

non_a_local_query_is_empty_noerror_test() ->
    Req = request("widget.local", txt),
    Resp = mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist)),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

request(Name, Type) ->
    #dns_rec{
        header = #dns_header{id = 7, rd = true},
        qdlist = [#dns_query{domain = Name, type = Type, class = in}]
    }.
