-module(mdns_dns_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_dns.hrl").

-define(LOCAL, [~"local"]).

%% Non-.local queries must come back NOERROR/empty, never REFUSED:
%% inet_res's nameservers -> alt_nameservers fallback only triggers on
%% NXDOMAIN or an empty-but-OK answer, never on REFUSED. See the README's
%% inet_db section and mdns_dns_server's module doc.
non_local_query_is_empty_noerror_test() ->
    Req = request("example.com", a),
    Resp = build(Req),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

%% A record type this bridge doesn't understand (unlike a/ptr/srv/txt) -
%% must not even try to resolve it, just fall through to empty NOERROR.
unsupported_type_local_query_is_empty_noerror_test() ->
    Req = request("widget.local", mx),
    Resp = build(Req),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

%% A packet with QR set is someone's response, not a query - answering it
%% would make this port usable as a reflector.
response_packets_are_ignored_test() ->
    #dns_rec{header = H} = Req = request("widget.local", a),
    ?assertEqual(
        ignore, mdns_dns_server:response_for(Req#dns_rec{header = H#dns_header{qr = true}}, ?LOCAL)
    ).

%% Opcode 5 (UPDATE) - anything but a standard query gets NOTIMP, with
%% the question echoed and nothing else.
non_query_opcode_gets_notimp_test() ->
    #dns_rec{header = H} = Req = request("widget.local", a),
    Resp = mdns_dns_server:response_for(Req#dns_rec{header = H#dns_header{opcode = 5}}, ?LOCAL),
    ?assertEqual(4, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual(1, (Resp#dns_rec.header)#dns_header.qr),
    ?assertEqual(Req#dns_rec.qdlist, Resp#dns_rec.qdlist),
    ?assertEqual([], Resp#dns_rec.anlist),
    %% ...and it survives the real encoder.
    ?assertMatch({ok, _}, inet_dns:decode(inet_dns:encode(Resp, false), false)).

empty_question_section_is_ignored_test() ->
    Req = request("widget.local", a),
    ?assertEqual(ignore, mdns_dns_server:response_for(Req#dns_rec{qdlist = []}, ?LOCAL)).

build(Req) ->
    build(Req, ?LOCAL).

build(Req, Domains) ->
    mdns_dns_server:build_response(Req, hd(Req#dns_rec.qdlist), Domains).

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
            fun resolves_txt_from_cache/0,
            fun resolves_non_ascii_name_from_cache/0,
            fun custom_domain_a/0,
            fun custom_domain_ptr_target_rewritten/0,
            fun custom_domain_srv_target_rewritten/0,
            fun custom_domain_leaves_non_local_targets/0,
            fun custom_domain_drops_overlong_rewrite/0,
            fun custom_domain_only_drops_local/0,
            fun custom_domain_alongside_local/0
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
    Resp = build(Req),
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
    Resp = build(Req),
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
    Resp = build(Req),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch([#dns_rr{type = txt, data = [~"path=/"]}], Resp#dns_rec.anlist).

%% A non-ASCII name: the cache key is the UTF-8 binary learned from the
%% wire, and the bridge question arrives as the same raw bytes in list
%% form - the two must meet, not miss because one side reinterpreted the
%% bytes as codepoints.
resolves_non_ascii_name_from_cache() ->
    ok = mdns_cache:insert_many([{<<"caf", 195, 169, ".local">>, a, {10, 0, 0, 9}, 120, false}]),
    Req = request([$c, $a, $f, 195, 169, $., $l, $o, $c, $a, $l], a),
    Resp = build(Req),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch([#dns_rr{type = a, data = {10, 0, 0, 9}}], Resp#dns_rec.anlist).

%% -- configurable bridge domains (dns_domains) ---------------------------

normalize_domains_test_() ->
    [
        ?_assertEqual({ok, [~"local"]}, mdns_dns_server:normalize_domains(["local"])),
        ?_assertEqual(
            {ok, [~"home.arpa"]}, mdns_dns_server:normalize_domains([~".Home.ARPA."])
        ),
        %% Most specific first, duplicates removed.
        ?_assertEqual(
            {ok, [~"home.arpa", ~"local", ~"arpa"]},
            mdns_dns_server:normalize_domains([~"arpa", ~"local", ~"home.arpa", "LOCAL"])
        ),
        ?_assertMatch({error, _}, mdns_dns_server:normalize_domains([])),
        ?_assertMatch({error, _}, mdns_dns_server:normalize_domains(~"local")),
        ?_assertMatch({error, {bad_domain, _}}, mdns_dns_server:normalize_domains([~"."])),
        ?_assertMatch({error, {bad_domain, _}}, mdns_dns_server:normalize_domains([~"a..b"])),
        ?_assertMatch({error, {bad_domain, _}}, mdns_dns_server:normalize_domains([local]))
    ].

-define(HOME, [~"home.arpa"]).

%% The question is answered under the name it was asked with, from the
%% `.local` record learned over mDNS - and survives the real encoder.
custom_domain_a() ->
    ok = mdns_cache:insert_many([{~"nas.local", a, {10, 0, 0, 7}, 120, false}]),
    Req = request("NAS.home.arpa", a),
    Resp = build(Req, ?HOME),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertMatch(
        [#dns_rr{domain = "NAS.home.arpa", type = a, data = {10, 0, 0, 7}}], Resp#dns_rec.anlist
    ),
    {ok, Decoded} = inet_dns:decode(inet_dns:encode(Resp, false), false),
    ?assertMatch([#dns_rr{domain = "NAS.home.arpa"}], Decoded#dns_rec.anlist).

custom_domain_ptr_target_rewritten() ->
    ok = mdns_cache:insert_many([
        {~"_ipp._tcp.local", ptr, ~"office printer._ipp._tcp.local", 4500, false}
    ]),
    Req = request("_ipp._tcp.home.arpa", ptr),
    Resp = build(Req, ?HOME),
    ?assertMatch(
        [#dns_rr{type = ptr, data = "office printer._ipp._tcp.home.arpa"}], Resp#dns_rec.anlist
    ).

custom_domain_srv_target_rewritten() ->
    ok = mdns_cache:insert_many([
        {~"office printer._ipp._tcp.local", srv, {0, 0, 631, ~"printer.local"}, 120, false}
    ]),
    Req = request("office printer._ipp._tcp.home.arpa", srv),
    Resp = build(Req, ?HOME),
    ?assertMatch(
        [#dns_rr{type = srv, data = {0, 0, 631, "printer.home.arpa"}}], Resp#dns_rec.anlist
    ),
    {ok, Decoded} = inet_dns:decode(inet_dns:encode(Resp, false), false),
    ?assertMatch(
        [#dns_rr{data = {0, 0, 631, "printer.home.arpa"}}], Decoded#dns_rec.anlist
    ).

%% A target outside `.local` - including one that only looks like it,
%% via an escaped dot - is handed back as-is.
custom_domain_leaves_non_local_targets() ->
    ok = mdns_cache:insert_many([
        {~"_web._tcp.local", ptr, ~"site._web._tcp.example.com", 120, false},
        {~"_web._tcp.local", ptr, ~"odd\\.local", 120, false}
    ]),
    Req = request("_web._tcp.home.arpa", ptr),
    Data = lists:sort([D || #dns_rr{data = D} <- (build(Req, ?HOME))#dns_rec.anlist]),
    ?assertEqual(["odd\\.local", "site._web._tcp.example.com"], Data).

%% Fits as `.local`, but not once the longer domain is substituted:
%% dropped rather than crashing the encoder. With nothing else to
%% answer, that's NXDOMAIN.
custom_domain_drops_overlong_rewrite() ->
    Label = binary:copy(~"x", 60),
    Long = iolist_to_binary(lists:join(~".", [Label, Label, Label, Label, ~"local"])),
    ?assertEqual(ok, mdns_proto:validate_name(Long)),
    ok = mdns_cache:insert_many([{~"_long._tcp.local", ptr, Long, 120, false}]),
    Domain = binary:copy(~"y", 20),
    Resp = build(request("_long._tcp." ++ binary_to_list(Domain), ptr), [Domain]),
    ?assertEqual([], Resp#dns_rec.anlist),
    ?assertEqual(3, (Resp#dns_rec.header)#dns_header.rcode).

%% With `.local` not configured, a `.local` question is outside the
%% bridge's domains: empty NOERROR, same as example.com.
custom_domain_only_drops_local() ->
    ok = mdns_cache:insert_many([{~"nas.local", a, {10, 0, 0, 7}, 120, false}]),
    Resp = build(request("nas.local", a), ?HOME),
    ?assertEqual(0, (Resp#dns_rec.header)#dns_header.rcode),
    ?assertEqual([], Resp#dns_rec.anlist).

custom_domain_alongside_local() ->
    ok = mdns_cache:insert_many([
        {~"_ipp._tcp.local", ptr, ~"office printer._ipp._tcp.local", 4500, false}
    ]),
    {ok, Domains} = mdns_dns_server:normalize_domains([~"local", ~"home.arpa"]),
    ?assertMatch(
        [#dns_rr{data = "office printer._ipp._tcp.local"}],
        (build(request("_ipp._tcp.local", ptr), Domains))#dns_rec.anlist
    ),
    ?assertMatch(
        [#dns_rr{data = "office printer._ipp._tcp.home.arpa"}],
        (build(request("_ipp._tcp.home.arpa", ptr), Domains))#dns_rec.anlist
    ).
