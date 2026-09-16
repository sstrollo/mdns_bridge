-module(mdns_proto_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_dns.hrl").

normalize_name_test_() ->
    [
        ?_assertEqual("foo.local", mdns_proto:normalize_name("Foo.Local")),
        ?_assertEqual("foo.local", mdns_proto:normalize_name("foo.local.")),
        ?_assertEqual("foo.local", mdns_proto:normalize_name(<<"FOO.LOCAL">>))
    ].

is_local_test_() ->
    [
        ?_assert(mdns_proto:is_local("foo.local")),
        ?_assert(mdns_proto:is_local("local")),
        ?_assertNot(mdns_proto:is_local("example.com")),
        ?_assertNot(mdns_proto:is_local("notlocal"))
    ].

mdns_answer_test() ->
    Rec = mdns_proto:mdns_answer("widget.local", a, [{{10, 0, 0, 1}, 120}]),
    ?assertEqual(1, (Rec#dns_rec.header)#dns_header.qr),
    ?assertEqual(1, (Rec#dns_rec.header)#dns_header.aa),
    ?assertEqual([], Rec#dns_rec.qdlist),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, ttl = 120, func = true}],
        Rec#dns_rec.anlist
    ).

round_trip_mdns_answer_test() ->
    Rec = mdns_proto:mdns_answer("widget.local", a, [{{10, 0, 0, 1}, 120}]),
    Bin = inet_dns:encode(Rec, true),
    {ok, Decoded} = inet_dns:decode(Bin, true),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, func = true}],
        Decoded#dns_rec.anlist
    ).

mdns_query_test() ->
    Rec = mdns_proto:mdns_query("widget.local", a),
    ?assertMatch(#dns_rec{qdlist = [#dns_query{domain = "widget.local", type = a}]}, Rec),
    [Q] = Rec#dns_rec.qdlist,
    ?assertNot(Q#dns_query.unicast_response).

extract_answers_test() ->
    RrA = #dns_rr{
        domain = "Widget.Local",
        type = a,
        class = in,
        ttl = 120,
        data = {10, 0, 0, 1},
        func = true
    },
    RrOther = #dns_rr{
        domain = "widget.local",
        type = a,
        class = chaos,
        ttl = 120,
        data = {10, 0, 0, 2}
    },
    Rec = #dns_rec{
        header = #dns_header{},
        qdlist = [],
        anlist = [RrA],
        nslist = [],
        arlist = [RrOther]
    },
    ?assertEqual(
        [{"widget.local", a, {10, 0, 0, 1}, 120, true}],
        mdns_proto:extract_answers(Rec)
    ).

dns_response_nxdomain_test() ->
    Req = request("missing.local", a),
    Resp = mdns_proto:dns_response(Req, [], a, false),
    ?assertEqual(3, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

dns_response_answers_test() ->
    Req = request("widget.local", a),
    Resp = mdns_proto:dns_response(Req, [{{10, 0, 0, 1}, 30}], a, true),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, ttl = 30}],
        Resp#dns_rec.anlist
    ).

%% Guards the assumption behind mdns_dns.hrl: it vendors inet_dns's own
%% record shapes (not published under kernel/include), so round-trip the
%% records we build through the real inet_dns:encode/decode. If a future
%% OTP release ever changes inet_dns's internal record layout, this is
%% what will actually catch it.
round_trip_mdns_query_test() ->
    Rec = mdns_proto:mdns_query("widget.local", a),
    Bin = inet_dns:encode(Rec, true),
    {ok, Decoded} = inet_dns:decode(Bin, true),
    ?assertMatch(#dns_rec{qdlist = [#dns_query{domain = "widget.local", type = a}]}, Decoded).

round_trip_dns_response_test() ->
    Req = request("widget.local", a),
    Resp = mdns_proto:dns_response(Req, [{{10, 0, 0, 1}, 30}], a, true),
    Bin = inet_dns:encode(Resp, false),
    {ok, Decoded} = inet_dns:decode(Bin, false),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, ttl = 30}],
        Decoded#dns_rec.anlist
    ).

request(Name, Type) ->
    #dns_rec{
        header = #dns_header{id = 42, rd = true},
        qdlist = [#dns_query{domain = Name, type = Type, class = in}]
    }.
