%%%-------------------------------------------------------------------
%% @doc Helpers for building/reading the #dns_rec{} terms that inet_dns
%% encodes/decodes, for both the mDNS side (Mdns=true) and the classic
%% unicast-DNS bridge side (Mdns=false).
%%
%% Names and domain-shaped data (a PTR's target, a SRV's target host)
%% are binaries everywhere in this app, except at the exact points they
%% cross into/out of inet_dns: its vendored record shapes (mdns_dns.hrl)
%% require a plain Erlang string() for any domain-name-shaped field -
%% confirmed empirically, not assumed - a binary domain crashes
%% encode/2 with function_clause in inet_dns:name2labels/1 - and
%% decode/2 always hands one back regardless of what was encoded. TXT
%% record strings are the one exception: inet_dns accepts binaries for
%% those directly at encode time (no per-string label-splitting
%% happens, unlike a domain name), so only the decode side needs a
%% conversion for TXT.
%% @end
%%%-------------------------------------------------------------------
-module(mdns_proto).

-include("mdns_dns.hrl").

-export([
    normalize_name/1,
    is_local/1,
    mdns_query/2,
    mdns_answer/3,
    probe_query/4,
    extract_answers/1,
    extract_watched_records/1,
    dns_response/4,
    escape_label/1,
    service_type_name/1,
    service_instance_name/2,
    build_txt_data/1,
    describe_data/2
]).

-define(CLASS_IN, in).
-define(LOCAL_SUFFIX, ~".local").

%% DNS names are case-insensitive; normalize for use as cache keys.
%% string:trim/3's "trailing" direction strips every trailing "." rather
%% than just one - a domain name would never legitimately have more than
%% one anyway, so that's a difference without a practical case.
-spec normalize_name(string() | binary()) -> binary().
normalize_name(Name) ->
    string:lowercase(string:trim(to_binary(Name), trailing, [$.])).

%% Name must already be normalize_name/1'd.
-spec is_local(binary()) -> boolean().
is_local(Name) ->
    Name =:= ~"local" orelse ends_with(Name, ?LOCAL_SUFFIX).

ends_with(Bin, Suffix) ->
    SuffixSize = byte_size(Suffix),
    byte_size(Bin) >= SuffixSize andalso
        binary:part(Bin, byte_size(Bin) - SuffixSize, SuffixSize) =:= Suffix.

%% Build an mDNS question packet (as a #dns_rec{}) asking for Type records
%% of Name. Plain (non-QU) question: we want the multicast answer, and it's
%% fine (and useful) if others on the link overhear it too.
-spec mdns_query(binary(), atom()) -> #dns_rec{}.
mdns_query(Name, Type) ->
    Header = #dns_header{id = 0, qr = 0, opcode = 0, rd = 0},
    Query = #dns_query{
        domain = to_domain(Name),
        type = Type,
        class = ?CLASS_IN,
        unicast_response = false
    },
    #dns_rec{header = Header, qdlist = [Query], anlist = [], nslist = [], arlist = []}.

%% Build an unsolicited mDNS answer/announcement (as a #dns_rec{}) for a
%% name we're publishing: an announce, a reactive answer to a matching
%% question, or (with Ttl=0) a goodbye. Per RFC 6762 section 6, multicast
%% responses conventionally omit the question section, and every answer
%% carries the cache-flush bit since we're the authority on our own
%% published records.
-spec mdns_answer(binary(), atom(), [{term(), non_neg_integer()}]) -> #dns_rec{}.
mdns_answer(Name, Type, Answers) ->
    Header = #dns_header{id = 0, qr = 1, opcode = 0, aa = 1},
    Domain = to_domain(Name),
    AnList = [
        #dns_rr{
            domain = Domain,
            type = Type,
            class = ?CLASS_IN,
            ttl = Ttl,
            data = to_wire_data(Type, Data),
            func = true
        }
     || {Data, Ttl} <- Answers
    ],
    #dns_rec{header = Header, qdlist = [], anlist = AnList, nslist = [], arlist = []}.

%% Build an RFC 6762 8.1 probe query: a question for Type records of Name,
%% with the record we intend to claim placed in the Authority section (not
%% Answer) so another simultaneous prober can see what we're proposing.
%% Never fed into the passive cache - see extract_watched_records/1.
-spec probe_query(binary(), atom(), term(), non_neg_integer()) -> #dns_rec{}.
probe_query(Name, Type, Data, Ttl) ->
    Domain = to_domain(Name),
    Header = #dns_header{id = 0, qr = 0, opcode = 0, rd = 0},
    Query = #dns_query{domain = Domain, type = Type, class = ?CLASS_IN, unicast_response = false},
    Proposed = #dns_rr{
        domain = Domain, type = Type, class = ?CLASS_IN, ttl = Ttl, data = to_wire_data(Type, Data)
    },
    #dns_rec{header = Header, qdlist = [Query], anlist = [], nslist = [Proposed], arlist = []}.

%% Pull out {Name, Type, Data, Ttl, CacheFlush} tuples for every answer
%% (answer + additional section) we're prepared to cache: class IN only.
-spec extract_answers(#dns_rec{}) ->
    [{binary(), atom(), term(), non_neg_integer(), boolean()}].
extract_answers(#dns_rec{anlist = An, arlist = Ar}) ->
    extract_records(An ++ Ar).

%% Like extract_answers/1, but also includes the Authority section - where
%% RFC 6762 puts a prober's tentatively-claimed records. Used only for
%% probe/conflict watching (mdns_socket); these are proposals, not
%% confirmed data, so they must never be fed into the passive cache the
%% way extract_answers/1's result is.
-spec extract_watched_records(#dns_rec{}) ->
    [{binary(), atom(), term(), non_neg_integer(), boolean()}].
extract_watched_records(#dns_rec{anlist = An, arlist = Ar, nslist = Ns}) ->
    extract_records(An ++ Ar ++ Ns).

extract_records(RRs) ->
    [
        {normalize_name(Domain), Type, from_wire_data(Type, Data), Ttl, CacheFlush}
     || #dns_rr{
            domain = Domain,
            type = Type,
            class = Class,
            data = Data,
            ttl = Ttl,
            func = CacheFlush
        } <- RRs,
        Class =:= ?CLASS_IN
    ].

%% inet_dns requires domain-name-shaped fields to be plain lists at
%% encode time and always hands one back at decode time (see the
%% moduledoc) - a PTR's data and a SRV's target are domain names too, so
%% they need the same conversion the domain field itself gets; anything
%% else (an address tuple, an opaque binary for a record type this app
%% doesn't otherwise understand) is passed through untouched. TXT is the
%% one exception on the *encode* side - inet_dns accepts binaries there
%% directly - but decode always hands back lists regardless of type, so
%% from_wire_data/2 still normalizes it back to our own binary form.
to_wire_data(ptr, Data) -> to_domain(Data);
to_wire_data(srv, {Prio, Weight, Port, Target}) -> {Prio, Weight, Port, to_domain(Target)};
to_wire_data(_Type, Data) -> Data.

from_wire_data(ptr, Data) -> normalize_name(Data);
from_wire_data(srv, {Prio, Weight, Port, Target}) -> {Prio, Weight, Port, normalize_name(Target)};
from_wire_data(txt, Data) when is_list(Data) -> [to_binary(S) || S <- Data];
from_wire_data(_Type, Data) -> Data.

to_domain(Name) -> unicode:characters_to_list(Name).

%% Escape a single DNS label's content per RFC 1035 presentation format -
%% also what inet_dns's own name encoder/decoder expects (see
%% inet_dns:name2labels/1): a literal "\" becomes "\\", a literal "."
%% becomes "\.". Needed for DNS-SD service instance names (RFC 6763
%% 4.1.3), which are free-form human-readable text and may contain
%% either - unescaped, a "." would be misread as a label separator when
%% the full name is built and handed to inet_dns. The two replacements
%% must run in this order (backslash first) and don't need to worry
%% about interfering with each other: binary:replace/4 only scans the
%% *original* input for each pass, never the text it just inserted.
-spec escape_label(string() | binary()) -> binary().
escape_label(Label) ->
    Escaped = binary:replace(to_binary(Label), ~"\\", ~"\\\\", [global]),
    binary:replace(Escaped, ~".", ~"\\.", [global]).

%% The DNS-SD service type name for ServiceType (e.g. "_http._tcp"),
%% e.g. ~"_http._tcp.local".
-spec service_type_name(string() | binary()) -> binary().
service_type_name(ServiceType) ->
    normalize_name(<<(to_binary(ServiceType))/binary, ?LOCAL_SUFFIX/binary>>).

%% The full DNS-SD service instance name for InstanceName under
%% ServiceType, e.g. service_instance_name("My Printer", "_http._tcp")
%% -> ~"my printer._http._tcp.local". InstanceName is escape_label/1'd
%% first, then - like every other name in this app - the whole result is
%% normalize_name/1'd, which lowercases it: display casing isn't
%% preserved, a known simplification (see the README).
-spec service_instance_name(string() | binary(), string() | binary()) -> binary().
service_instance_name(InstanceName, ServiceType) ->
    normalize_name(<<
        (escape_label(InstanceName))/binary, ".", (service_type_name(ServiceType))/binary
    >>).

%% The list-of-binaries wire representation for a TXT record, from a list
%% of {Key, Value} pairs (encoded as "Key=Value") and/or plain
%% strings/binaries (used as-is, for a boolean-style key with no value -
%% RFC 6763 6.4). An empty list becomes a single empty string - RFC 6763
%% 6.1 requires at least one string, even to represent "no data".
-spec build_txt_data([{iodata(), iodata()} | iodata()]) -> [binary()].
build_txt_data([]) ->
    [<<>>];
build_txt_data(KVs) ->
    [txt_entry(KV) || KV <- KVs].

txt_entry({Key, Value}) -> <<(to_binary(Key))/binary, "=", (to_binary(Value))/binary>>;
txt_entry(Plain) -> to_binary(Plain).

to_binary(S) when is_binary(S) -> S;
to_binary(S) when is_list(S) -> unicode:characters_to_binary(S).

%% Describes Data for a human, keyed off Type - used by mdns_cache:print/1
%% (kept here, not there: interpreting what a record type's data means on
%% the wire is exactly this module's job everywhere else too). Returns
%% either {inline, IoData} for one line, or {multiline, [IoData]} for a
%% TXT record with more than one string - see the txt clause. Anything
%% this app doesn't have a specific reading for - an unrecognized type,
%% or data that doesn't match a known type's expected shape - falls back
%% to a plain ~0p dump rather than guessing wrong or crashing.
-spec describe_data(atom() | non_neg_integer(), term()) ->
    {inline, iodata()} | {multiline, [iodata()]}.
%% a/aaaa: a dotted-quad or colon-hex address string, not a raw tuple.
describe_data(Type, Data) when Type =:= a; Type =:= aaaa ->
    case inet:ntoa(Data) of
        {error, _} -> {inline, io_lib:format("~0p", [Data])};
        Address -> {inline, Address}
    end;
%% ptr: just the target name, unquoted.
describe_data(ptr, Data) when is_binary(Data) ->
    {inline, Data};
%% srv: labeled fields, target unquoted - the priority/weight/port order
%% on the wire isn't obvious to read without labels the way an a/ptr
%% record's single value is.
describe_data(srv, {Priority, Weight, Port, Target}) ->
    {inline,
        io_lib:format("priority=~b weight=~b port=~b target=~ts", [
            Priority, Weight, Port, Target
        ])};
%% txt: unquoted, and - since a real TXT record can hold a couple dozen
%% strings (e.g. a printer's IPP capabilities) - one per (indented) line
%% once there's more than a single entry to keep scannable, rather than
%% cramming them all onto the entry's own line.
describe_data(txt, []) ->
    {inline, <<>>};
describe_data(txt, [Entry]) when is_binary(Entry) ->
    {inline, Entry};
describe_data(txt, Data) when is_list(Data) ->
    {multiline, Data};
%% nsec (47): see describe_nsec/1.
describe_data(47, Data) when is_binary(Data) ->
    describe_nsec(Data);
describe_data(_Type, Data) ->
    {inline, io_lib:format("~0p", [Data])}.

%% RFC 4034/3845: NSEC's data is a "next domain name" (frequently
%% compressed - a 2-byte pointer this app can't resolve, since inet_dns
%% only ever hands us this one record's own rdata, not the whole packet
%% it came from - see skip_dns_name/1) followed by one or more
%% {window, bitmap} blocks marking which record types exist for this
%% name. This shows up constantly in real mDNS traffic as the common
%% idiom for asserting "these are ALL the types I have here" (e.g.
%% "srv,txt" for a service instance, "a,aaaa" for a plain dual-stack
%% host) - a negative-answer optimization, not real DNSSEC validation.
%% The name itself isn't shown: not generically resolvable when
%% compressed, and not useful to a human either - just the types, which
%% are self-contained regardless of how the name portion was encoded.
describe_nsec(Data) ->
    case skip_dns_name(Data) of
        {ok, Rest} ->
            case decode_nsec_windows(Rest, []) of
                {ok, Types} ->
                    {inline, [
                        <<"types=">>, lists:join(",", [type_name(T) || T <- Types])
                    ]};
                error ->
                    {inline, io_lib:format("~0p", [Data])}
            end;
        error ->
            {inline, io_lib:format("~0p", [Data])}
    end.

%% Walks an RFC 1035 name - a sequence of length-prefixed labels (1-63
%% bytes each) ending in either a zero-length root label or a 2-byte
%% compression pointer (the top 2 bits of the next byte set) - far
%% enough to find where it ends, without resolving what a pointer
%% actually points to (impossible from a single record's rdata alone).
skip_dns_name(<<Len, _Label:Len/binary, Rest/binary>>) when Len > 0, Len =< 63 ->
    skip_dns_name(Rest);
skip_dns_name(<<0, Rest/binary>>) ->
    {ok, Rest};
skip_dns_name(<<Top:2, _:14, Rest/binary>>) when Top =:= 2#11 ->
    {ok, Rest};
skip_dns_name(_Other) ->
    error.

decode_nsec_windows(<<>>, Acc) ->
    {ok, lists:usort(lists:append(lists:reverse(Acc)))};
decode_nsec_windows(<<Window, BitmapLen, Bitmap:BitmapLen/binary, Rest/binary>>, Acc) when
    BitmapLen >= 1, BitmapLen =< 32
->
    decode_nsec_windows(Rest, [bitmap_types(Window, Bitmap) | Acc]);
decode_nsec_windows(_Other, _Acc) ->
    error.

%% Each window covers 256 type numbers (Window*256 .. Window*256+255);
%% within the bitmap, bit 0 of byte 0 is type Window*256+0, counting
%% down from the most significant bit of each byte (RFC 4034 4.1.2).
bitmap_types(Window, Bitmap) ->
    [
        Window * 256 + ByteIndex * 8 + BitIndex
     || {ByteIndex, Byte} <- lists:enumerate(0, binary_to_list(Bitmap)),
        BitIndex <- lists:seq(0, 7),
        (Byte bsr (7 - BitIndex)) band 1 =:= 1
    ].

%% Common DNS RR type numbers, for NSEC's type bitmap - falls back to
%% the bare number for anything not worth naming here.
type_name(1) -> "a";
type_name(2) -> "ns";
type_name(5) -> "cname";
type_name(6) -> "soa";
type_name(12) -> "ptr";
type_name(13) -> "hinfo";
type_name(15) -> "mx";
type_name(16) -> "txt";
type_name(17) -> "rp";
type_name(24) -> "sig";
type_name(25) -> "key";
type_name(28) -> "aaaa";
type_name(29) -> "loc";
type_name(33) -> "srv";
type_name(35) -> "naptr";
type_name(36) -> "kx";
type_name(37) -> "cert";
type_name(39) -> "dname";
type_name(41) -> "opt";
type_name(43) -> "ds";
type_name(44) -> "sshfp";
type_name(45) -> "ipseckey";
type_name(46) -> "rrsig";
type_name(47) -> "nsec";
type_name(48) -> "dnskey";
type_name(50) -> "nsec3";
type_name(51) -> "nsec3param";
type_name(52) -> "tlsa";
type_name(59) -> "cds";
type_name(60) -> "cdnskey";
type_name(61) -> "openpgpkey";
type_name(64) -> "svcb";
type_name(65) -> "https";
type_name(99) -> "spf";
type_name(249) -> "tkey";
type_name(250) -> "tsig";
type_name(255) -> "any";
type_name(256) -> "uri";
type_name(257) -> "caa";
type_name(Other) -> integer_to_list(Other).

%% Build a classic unicast-DNS response for the bridge server.
%% Answers :: [{Data, Ttl}] for the queried Name/Type. Domain comes
%% straight from the request's own (already-decoded, so already a list)
%% question section - only Data, sourced from our own binary-keyed
%% cache/registry, needs converting back to wire shape.
-spec dns_response(#dns_rec{}, [{term(), non_neg_integer()}], atom(), boolean()) ->
    #dns_rec{}.
dns_response(#dns_rec{header = ReqHeader, qdlist = Qd}, Answers, Type, Found) ->
    Rcode =
        case {Found, Answers} of
            {true, _} -> 0;
            % NXDOMAIN
            {false, []} -> 3;
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
        #dns_rr{
            domain = Domain,
            type = Type,
            class = ?CLASS_IN,
            ttl = Ttl,
            data = to_wire_data(Type, Data)
        }
     || #dns_query{domain = Domain} <- Qd, {Data, Ttl} <- Answers
    ],
    #dns_rec{header = RespHeader, qdlist = Qd, anlist = AnList, nslist = [], arlist = []}.
