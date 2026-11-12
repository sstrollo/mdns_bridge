-module(mdns_proto_tests).

-include_lib("eunit/include/eunit.hrl").
-include("mdns_dns.hrl").

normalize_name_test_() ->
    [
        ?_assertEqual(~"foo.local", mdns_proto:normalize_name("Foo.Local")),
        ?_assertEqual(~"foo.local", mdns_proto:normalize_name("foo.local.")),
        ?_assertEqual(~"foo.local", mdns_proto:normalize_name(~"FOO.LOCAL")),
        %% Multiple trailing dots are all stripped.
        ?_assertEqual(~"foo.local", mdns_proto:normalize_name(~"foo.local..")),
        %% UTF-8 multi-byte content is passed through untouched (ASCII-only
        %% case folding) rather than Unicode-case-folded.
        ?_assertEqual(
            unicode:characters_to_binary("café.local"),
            mdns_proto:normalize_name(unicode:characters_to_binary("café.local"))
        ),
        %% A wire name that is NOT valid UTF-8 (a label byte of 0xFF is
        %% legal on the wire, invalid UTF-8) must normalize without
        %% crashing - string:lowercase/1 would throw badarg here, which on
        %% the inbound path would crash mdns_socket. See
        %% malformed_name_inbound_does_not_crash_test/0.
        ?_assertEqual(
            <<16#ff, ".local">>, mdns_proto:normalize_name(<<16#ff, ".LOCAL.">>)
        )
    ].

%% A crafted inbound mDNS record whose name contains a non-UTF-8 byte must
%% be processed by the real extract_answers/1 path (the one mdns_socket
%% runs on every packet) without raising - otherwise a single multicast
%% packet from anyone on the segment crashes the socket gen_server.
malformed_name_inbound_does_not_crash_test() ->
    Rr = #dns_rr{
        domain = [16#ff | "local"],
        type = a,
        class = in,
        ttl = 120,
        data = {10, 0, 0, 1},
        func = true
    },
    Rec = #dns_rec{header = #dns_header{}, anlist = [Rr], arlist = []},
    ?assertEqual(
        [{<<16#ff, "local">>, a, {10, 0, 0, 1}, 120, true}],
        mdns_proto:extract_answers(Rec)
    ).

validate_name_test_() ->
    Label63 = binary:copy(~"a", 63),
    Label64 = binary:copy(~"a", 64),
    %% 4 x 62-byte labels: 4 * (1 + 62) + 1 = 253 wire bytes, fits.
    Name253 = iolist_to_binary(lists:join(".", [binary:copy(~"b", 62) || _ <- lists:seq(1, 4)])),
    %% 4 x 63-byte labels: 4 * 64 + 1 = 257, doesn't.
    Name257 = iolist_to_binary(lists:join(".", [Label63 || _ <- lists:seq(1, 4)])),
    [
        ?_assertEqual(ok, mdns_proto:validate_name(~"printer.local")),
        ?_assertEqual(ok, mdns_proto:validate_name(<<Label63/binary, ".local">>)),
        ?_assertEqual(
            {error, label_too_long}, mdns_proto:validate_name(<<Label64/binary, ".local">>)
        ),
        ?_assertEqual({error, empty_label}, mdns_proto:validate_name(~"foo..local")),
        ?_assertEqual({error, empty_label}, mdns_proto:validate_name(~".local")),
        ?_assertEqual({error, empty_label}, mdns_proto:validate_name(<<>>)),
        ?_assertEqual(ok, mdns_proto:validate_name(Name253)),
        ?_assertEqual({error, name_too_long}, mdns_proto:validate_name(Name257)),
        %% Escapes count as one wire byte: 62 chars + "\." = 63 bytes on
        %% the wire even though the binary is 64 long (63 + "\." is 64,
        %% too long); and a lone escaped dot is a 1-byte label, not an
        %% empty one.
        ?_assertEqual(
            ok, mdns_proto:validate_name(<<(binary:copy(~"c", 62))/binary, "\\.._http._tcp.local">>)
        ),
        ?_assertEqual(
            {error, label_too_long},
            mdns_proto:validate_name(<<(binary:copy(~"c", 63))/binary, "\\.._http._tcp.local">>)
        ),
        ?_assertEqual(ok, mdns_proto:validate_name(~"\\.._http._tcp.local"))
    ].

validate_txt_data_test_() ->
    [
        ?_assertEqual(ok, mdns_proto:validate_txt_data([<<>>])),
        ?_assertEqual(ok, mdns_proto:validate_txt_data([~"a=b", binary:copy(~"k", 255)])),
        ?_assertMatch(
            {error, {txt_string_too_long, _}},
            mdns_proto:validate_txt_data([~"a=b", binary:copy(~"k", 256)])
        )
    ].

is_local_test_() ->
    [
        ?_assert(mdns_proto:is_local(~"foo.local")),
        ?_assert(mdns_proto:is_local(~"local")),
        ?_assertNot(mdns_proto:is_local(~"example.com")),
        ?_assertNot(mdns_proto:is_local(~"notlocal"))
    ].

mdns_answer_test() ->
    Rec = mdns_proto:mdns_answer(~"widget.local", a, [{{10, 0, 0, 1}, 120}]),
    ?assertEqual(1, (Rec#dns_rec.header)#dns_header.qr),
    ?assertEqual(1, (Rec#dns_rec.header)#dns_header.aa),
    ?assertEqual([], Rec#dns_rec.qdlist),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, ttl = 120, func = true}],
        Rec#dns_rec.anlist
    ).

round_trip_mdns_answer_test() ->
    Rec = mdns_proto:mdns_answer(~"widget.local", a, [{{10, 0, 0, 1}, 120}]),
    Bin = inet_dns:encode(Rec, true),
    {ok, Decoded} = inet_dns:decode(Bin, true),
    ?assertMatch(
        [#dns_rr{domain = "widget.local", type = a, data = {10, 0, 0, 1}, func = true}],
        Decoded#dns_rec.anlist
    ).

mdns_query_test() ->
    Rec = mdns_proto:mdns_query(~"widget.local", a),
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
        [{~"widget.local", a, {10, 0, 0, 1}, 120, true}],
        mdns_proto:extract_answers(Rec)
    ).

%% Real bug, caught from a real LAN capture: inet_dns:decode/2 hands a
%% domain-name-shaped field back as a list of *raw wire bytes*, not
%% Unicode codepoints - "o with diaeresis" (U+00F6) is 2 list elements,
%% [195,182] (its UTF-8 encoding), not one element holding 246.
%% Treating that list as if it held codepoints (as a genuine
%% caller-supplied Erlang string would) and UTF-8-*encoding* it again
%% corrupts every multi-byte character: "ö" came out as 4 bytes,
%% [195,163,194,182], not the correct 2. Round-trips real bytes through
%% the real inet_dns:encode/decode, then extract_answers/1, rather than
%% just unit-testing the conversion helper in isolation - this is
%% exactly the shape a real device's announcement takes.
round_trip_utf8_ptr_data_test() ->
    %% "tillh" + o-with-diaeresis (correctly UTF-8-encoded: 195, 182) + "r"
    RawLabel = "tillh" ++ [195, 182] ++ "r",
    Rr = #dns_rr{
        domain = "_airplay._tcp.local",
        type = ptr,
        class = in,
        ttl = 120,
        data = RawLabel ++ "._airplay._tcp.local",
        func = true
    },
    Rec = #dns_rec{
        header = #dns_header{}, qdlist = [], anlist = [Rr], nslist = [], arlist = []
    },
    Bin = inet_dns:encode(Rec, true),
    {ok, Decoded} = inet_dns:decode(Bin, true),
    [{_Name, ptr, Data, _Ttl, _CacheFlush}] = mdns_proto:extract_answers(Decoded),
    Expected = <<"tillh", 195, 182, "r._airplay._tcp.local">>,
    ?assertEqual(Expected, Data).

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
    Rec = mdns_proto:mdns_query(~"widget.local", a),
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

%% dns_response/4's Domain comes straight from the request's own
%% (decoded, so already a list) question section - this helper builds
%% that request directly rather than through mdns_proto:mdns_query/2, so
%% it stays a plain string like a real decoded packet would be.
request(Name, Type) ->
    #dns_rec{
        header = #dns_header{id = 42, rd = true},
        qdlist = [#dns_query{domain = Name, type = Type, class = in}]
    }.

escape_label_test_() ->
    [
        ?_assertEqual(~"plain", mdns_proto:escape_label("plain")),
        ?_assertEqual(~"my\\.printer", mdns_proto:escape_label("my.printer")),
        ?_assertEqual(~"back\\\\slash", mdns_proto:escape_label("back\\slash")),
        ?_assertEqual(
            ~"both\\\\and\\.dot", mdns_proto:escape_label("both\\and.dot")
        )
    ].

service_type_name_test() ->
    ?assertEqual(~"_http._tcp.local", mdns_proto:service_type_name("_http._tcp")).

service_instance_name_test_() ->
    [
        ?_assertEqual(
            ~"my printer._http._tcp.local",
            mdns_proto:service_instance_name("My Printer", "_http._tcp")
        ),
        ?_assertEqual(
            ~"my\\.printer._http._tcp.local",
            mdns_proto:service_instance_name("My.Printer", "_http._tcp")
        )
    ].

%% Round-trip a service instance name containing a literal "." through
%% the real inet_dns encoder/decoder - the whole reason escape_label/1
%% exists is to survive exactly this, not just look right as a string.
%% Decoded#dns_rec's domain is always a plain list (that's inet_dns's
%% own wire-decode shape - see mdns_proto's moduledoc), so it's
%% normalize_name/1'd back to binary before comparing against Name.
round_trip_escaped_instance_name_test() ->
    Name = mdns_proto:service_instance_name("3.5\" Drive", "_http._tcp"),
    Rec = mdns_proto:mdns_answer(Name, ptr, [{~"target.local", 4500}]),
    Bin = inet_dns:encode(Rec, true),
    {ok, Decoded} = inet_dns:decode(Bin, true),
    [#dns_rr{domain = DecodedDomain}] = Decoded#dns_rec.anlist,
    ?assertEqual(Name, mdns_proto:normalize_name(DecodedDomain)).

build_txt_data_test_() ->
    [
        ?_assertEqual([<<>>], mdns_proto:build_txt_data([])),
        ?_assertEqual([~"path=/"], mdns_proto:build_txt_data([{"path", "/"}])),
        ?_assertEqual(
            [~"path=/", ~"flag"], mdns_proto:build_txt_data([{"path", "/"}, "flag"])
        ),
        ?_assertEqual(
            [~"a=1"], mdns_proto:build_txt_data([{~"a", ~"1"}])
        )
    ].

describe_data_test_() ->
    [
        ?_assertEqual({inline, ~"192.168.1.1"}, describe(a, {192, 168, 1, 1})),
        ?_assertEqual({inline, ~"fe80::1"}, describe(aaaa, {65152, 0, 0, 0, 0, 0, 0, 1})),
        %% not a valid address for the type - falls back to a raw dump
        %% rather than crashing print/1 over it
        ?_assertEqual({inline, ~"not_an_address"}, describe(a, not_an_address)),
        ?_assertEqual({inline, ~"widget.local"}, describe(ptr, ~"widget.local")),
        ?_assertEqual(
            {inline, ~"priority=0 weight=0 port=8080 target=widget.local"},
            describe(srv, {0, 0, 8080, ~"widget.local"})
        ),
        ?_assertEqual({inline, <<>>}, describe(txt, [])),
        ?_assertEqual({inline, ~"path=/"}, describe(txt, [~"path=/"])),
        ?_assertEqual(
            {multiline, [~"a=1", ~"b=2"]}, describe(txt, [~"a=1", ~"b=2"])
        ),
        %% a record type this app doesn't understand at all - raw dump
        ?_assertEqual({inline, ~"<<1,2,3>>"}, describe(99, <<1, 2, 3>>))
    ].

%% Byte shapes anonymized from a real LAN's NSEC (type 47) traffic -
%% only device/host names changed, the wire structure (compressed vs.
%% uncompressed next-name, single- vs. multi-type bitmaps) is real.
describe_nsec_test_() ->
    [
        %% compressed next-name (a 2-byte 0xC0.. pointer) + a single-type
        %% bitmap - the common shape for a plain host's own NSEC record
        ?_assertEqual({inline, ~"types=a"}, describe(47, <<192, 12, 0, 1, 64>>)),
        ?_assertEqual({inline, ~"types=ptr"}, describe(47, <<192, 12, 0, 2, 0, 8>>)),
        %% two types in one bitmap byte-range - the common shape for a
        %% DNS-SD service instance (SRV + TXT)
        ?_assertEqual(
            {inline, ~"types=txt,srv"}, describe(47, <<192, 43, 0, 5, 0, 0, 128, 0, 64>>)
        ),
        %% uncompressed next-name (length-prefixed labels, "weird1.local")
        %% ending in the root label, rather than a compression pointer
        ?_assertEqual(
            {inline, ~"types=aaaa"},
            describe(
                47,
                <<6, 119, 101, 105, 114, 100, 49, 5, 108, 111, 99, 97, 108, 0, 0, 4, 0, 0, 0, 8>>
            )
        ),
        %% malformed rdata - falls back to a raw dump, doesn't crash
        ?_assertMatch({inline, _}, describe(47, <<1, 2>>))
    ].

describe(Type, Data) ->
    case mdns_proto:describe_data(Type, Data) of
        {inline, IoData} -> {inline, iolist_to_binary(IoData)};
        {multiline, Entries} -> {multiline, [iolist_to_binary(E) || E <- Entries]}
    end.

%% Used both for describe_nsec/1's type list and directly by
%% mdns_cache:print/1 for the type column, so an atom inet_dns already
%% recognizes (a, ptr, ...) and a bare integer it doesn't (like 47 -
%% NSEC isn't one inet_dns maps to an atom) both need to come out
%% right, and both as a binary, not a string() - see CLAUDE.md.
type_name_test_() ->
    [
        ?_assertEqual(~"a", mdns_proto:type_name(a)),
        ?_assertEqual(~"srv", mdns_proto:type_name(srv)),
        ?_assert(is_binary(mdns_proto:type_name(a))),
        ?_assertEqual(~"nsec", mdns_proto:type_name(47)),
        ?_assertEqual(~"ptr", mdns_proto:type_name(12)),
        %% a type number with no entry in the table at all
        ?_assertEqual(~"1234", mdns_proto:type_name(1234)),
        %% an atom inet_dns has never heard of either - still just its
        %% own name, not a crash
        ?_assertEqual(~"made_up_type", mdns_proto:type_name(made_up_type))
    ].

%% Only the first question is resolved by the bridge, so only it may be
%% echoed and answered - pairing the answers with a second question would
%% hand out an authoritative record for a name never looked up.
dns_response_multi_question_test() ->
    Req = #dns_rec{
        header = #dns_header{id = 7, rd = true},
        qdlist = [
            #dns_query{domain = "foo.local", type = a, class = in},
            #dns_query{domain = "bar.example.com", type = a, class = in}
        ]
    },
    Resp = mdns_proto:dns_response(Req, [{{10, 0, 0, 1}, 30}], a, true),
    ?assertMatch([#dns_query{domain = "foo.local"}], Resp#dns_rec.qdlist),
    ?assertMatch([#dns_rr{domain = "foo.local", data = {10, 0, 0, 1}}], Resp#dns_rec.anlist).

%% A name binary holds the exact bytes that belong on the wire; encode
%% must emit them unchanged (UTF-8 stays UTF-8, not Latin-1) and decode
%% must give back the identical binary.
non_ascii_name_round_trip_test_() ->
    [
        ?_assertEqual(Name, round_trip_query_name(Name))
     || Name <- [
            %% "café.local" (é = U+00E9, UTF-8 C3 A9)
            <<"caf", 195, 169, ".local">>,
            %% U+4E2D, above U+00FF: used to crash encode/2
            <<228, 184, 173, ".local">>,
            %% not valid UTF-8 at all: still just bytes
            <<16#ff, ".local">>
        ]
    ].

round_trip_query_name(Name) ->
    Bin = inet_dns:encode(mdns_proto:mdns_query(Name, a), true),
    {ok, #dns_rec{qdlist = [#dns_query{domain = Domain}]}} = inet_dns:decode(Bin, true),
    mdns_proto:normalize_wire_name(Domain).

%% PTR/SRV targets learned from the network can be any bytes; serving
%% them over the bridge must encode, not crash with function_clause.
dns_response_non_utf8_ptr_target_encodes_test() ->
    Req = request("x.local", ptr),
    Target = <<16#ff, "svc.local">>,
    Resp = mdns_proto:dns_response(Req, [{Target, 30}], ptr, true),
    {ok, Decoded} = inet_dns:decode(inet_dns:encode(Resp, false), false),
    [#dns_rr{data = Data}] = Decoded#dns_rec.anlist,
    ?assertEqual(Target, mdns_proto:normalize_wire_name(Data)).

%% Question names arrive as raw wire bytes; normalize_wire_name/1 must
%% not reinterpret them as codepoints (normalize_name/1 on the same list
%% would double-encode the UTF-8).
normalize_wire_name_test() ->
    ?assertEqual(
        <<"caf", 195, 169, ".local">>,
        mdns_proto:normalize_wire_name([$C, $a, $f, 195, 169, $., $l, $o, $c, $a, $l, $.])
    ).
