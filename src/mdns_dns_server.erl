-module(mdns_dns_server).

-moduledoc """
Classic unicast-DNS bridge for the `.local` domain (or other
configured domains, see below). Listens on a
plain UDP port (not 53, not 5353) and answers A/PTR/SRV/TXT queries
from `mdns_cache`/`mdns_query` - this is the socket an upstream
resolver (e.g. dnsmasq, systemd-resolved, or Erlang's own `inet_db` -
see the README) forwards `.local` queries to.

The domains answered are configurable (`dns_domains`, default
`["local"]`), so the bridge can serve e.g. `home.arpa` (RFC 8375)
instead of, or as well as, `.local`. mDNS itself only ever speaks
`.local`, so this is a name translation at the bridge's edge, in the
manner of an RFC 8766 discovery proxy: a question for
`printer.home.arpa` is resolved as `printer.local`, and `.local`
names inside the answer (a PTR's target, a SRV's target host) are
rewritten back into `home.arpa`. TXT data is never rewritten.

For anything outside the configured domains we deliberately reply
NOERROR with an empty answer section rather than REFUSED. That's not
just politeness: OTP's `inet_res` only falls back from its
`nameservers` list to its `alt_nameservers` list on NXDOMAIN or on an
empty-but-OK answer, never on REFUSED (see `inet_res`'s internal
query_nss_result/9 and res_query/5 functions, in the kernel app).
Replying REFUSED would make this server usable as a bridge-only
nameserver but permanently break split-horizon setups that
put it in `nameservers` and a real resolver in `alt_nameservers`.

Each request is handled in its own short-lived process so a slow
on-demand mDNS lookup for one query can't stall others - but that
means an unbounded flood of inbound packets would spawn an unbounded
number of processes, and each cache-miss `.local` query also puts a
multicast mDNS query out onto the LAN. `dns_rate_limit_per_second`
caps how many requests we'll actually act on per second (the rest are
simply dropped, same as a lost UDP packet); anyone who can reach this
port cannot use it to cheaply flood the multicast segment or exhaust
the process table beyond that budget.
""".

-behaviour(gen_server).

-include("mdns_dns.hrl").

-export([child_spec/0, start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([response_for/2, build_response/3, should_accept/2, normalize_domains/1]).

-define(SERVER, ?MODULE).
-define(DEFAULT_PORT, 8053).
-define(DEFAULT_BIND_IP, {0, 0, 0, 0}).
-define(DEFAULT_ANSWER_TTL, 30).
-define(DEFAULT_QUERY_TIMEOUT_MS, 400).
-define(DEFAULT_RATE_LIMIT_PER_SECOND, 1000).
-define(DEFAULT_DOMAINS, [~"local"]).
-define(RATE_WINDOW_MS, 1000).
%% {active, N}: bounds this process's mailbox under a flood - see
%% mdns_socket, which does the same.
-define(ACTIVE_N, 100).
%% Record types this bridge actually understands and will actively
%% resolve on a cache miss. Anything else (including AAAA - IPv6 isn't
%% supported yet) falls through to the generic empty-NOERROR path below.
-define(SUPPORTED_TYPES, [a, ptr, srv, txt]).

-record(state, {
    socket :: gen_udp:socket(),
    domains :: [binary(), ...],
    rate_limit :: pos_integer() | infinity,
    count = 0 :: non_neg_integer()
}).

child_spec() ->
    #{id => ?MODULE, start => {?MODULE, start_link, []}}.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    case normalize_domains(application:get_env(mdns_bridge, dns_domains, ?DEFAULT_DOMAINS)) of
        {ok, Domains} -> open_socket(Domains);
        {error, Reason} -> {stop, {invalid_dns_domains, Reason}}
    end.

open_socket(Domains) ->
    Port = application:get_env(mdns_bridge, dns_port, ?DEFAULT_PORT),
    BindIp = application:get_env(mdns_bridge, dns_bind_ip, ?DEFAULT_BIND_IP),
    RateLimit = application:get_env(
        mdns_bridge, dns_rate_limit_per_second, ?DEFAULT_RATE_LIMIT_PER_SECOND
    ),
    %% No reuseaddr: UDP has no TIME_WAIT to work around, and on Linux
    %% SO_REUSEADDR would let any other local process bind the same
    %% port and take the bridge's queries away from it.
    Opts = [binary, {active, ?ACTIVE_N}, {ip, BindIp}],
    case gen_udp:open(Port, Opts) of
        {ok, Socket} ->
            logger:info("mdns_dns_server: listening on ~0p:~b for ~0p", [BindIp, Port, Domains]),
            schedule_rate_reset(),
            {ok, #state{socket = Socket, domains = Domains, rate_limit = RateLimit}};
        {error, Reason} ->
            {stop, {socket_open_failed, Reason}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(
    {udp, Socket, SrcIp, SrcPort, Packet},
    #state{socket = Socket, domains = Domains, rate_limit = RateLimit, count = Count} = State
) ->
    case should_accept(RateLimit, Count) of
        true ->
            spawn(fun() -> handle_query(Socket, SrcIp, SrcPort, Packet, Domains) end),
            {noreply, State#state{count = Count + 1}};
        false ->
            %% Over budget for this window: drop it, same as a lost
            %% UDP packet - the caller's own retry/timeout handles it.
            {noreply, State}
    end;
handle_info({udp_passive, Socket}, #state{socket = Socket} = State) ->
    ok = inet:setopts(Socket, [{active, ?ACTIVE_N}]),
    {noreply, State};
handle_info(reset_rate_counter, State) ->
    schedule_rate_reset(),
    {noreply, State#state{count = 0}};
handle_info(_Msg, State) ->
    {noreply, State}.

-doc "Whether a request should be accepted given RateLimit and the current window's Count so far.".
-spec should_accept(pos_integer() | infinity, non_neg_integer()) -> boolean().
should_accept(infinity, _Count) -> true;
should_accept(RateLimit, Count) -> Count < RateLimit.

schedule_rate_reset() ->
    erlang:send_after(?RATE_WINDOW_MS, self(), reset_rate_counter).

-doc """
Validate and normalize the `dns_domains` setting: a non-empty list of
domain names (strings or binaries; case and leading/trailing dots
don't matter). Returned most specific first, so a name under two
configured domains (`arpa` and `home.arpa`) maps via the longer one.
""".
-spec normalize_domains(term()) -> {ok, [binary(), ...]} | {error, term()}.
normalize_domains([_ | _] = Domains0) ->
    try [normalize_domain(D) || D <- Domains0] of
        Domains ->
            BySpecificity = lists:sort(fun(A, B) -> byte_size(A) >= byte_size(B) end, Domains),
            {ok, lists:uniq(BySpecificity)}
    catch
        throw:Reason -> {error, Reason}
    end;
normalize_domains(Other) ->
    {error, {not_a_non_empty_list, Other}}.

normalize_domain(Domain0) when is_binary(Domain0); is_list(Domain0) ->
    Domain = string:trim(mdns_proto:normalize_name(Domain0), leading, "."),
    case Domain =/= ~"" andalso mdns_proto:validate_name(Domain) of
        ok -> Domain;
        _ -> throw({bad_domain, Domain0})
    end;
normalize_domain(Other) ->
    throw({bad_domain, Other}).

%% -- request handling (runs in its own process) ------------------------

handle_query(Socket, SrcIp, SrcPort, Packet, Domains) ->
    case inet_dns:decode(Packet, false) of
        {ok, Req} ->
            case response_for(Req, Domains) of
                ignore -> ok;
                Response -> reply(Socket, SrcIp, SrcPort, Response)
            end;
        {error, _Reason} ->
            ok
    end.

-doc """
The response to send for a decoded request, or `ignore`. A packet
that is itself a response (QR set) gets nothing - replying to one
would make this port a reflector that two servers could be pointed at
each other through; an opcode other than a standard query gets NOTIMP;
a request without a question gets nothing.
""".
-spec response_for(#dns_rec{}, [binary(), ...]) -> #dns_rec{} | ignore.
response_for(#dns_rec{header = #dns_header{qr = true}}, _Domains) ->
    ignore;
response_for(#dns_rec{header = #dns_header{opcode = Opcode}} = Req, _Domains) when
    Opcode =/= 'query', Opcode =/= 0
->
    mdns_proto:dns_error_response(Req, notimp);
response_for(#dns_rec{qdlist = [Q | _]} = Req, Domains) ->
    build_response(Req, Q, Domains);
response_for(#dns_rec{qdlist = []}, _Domains) ->
    ignore.

-doc """
Build the DNS response for query Q of request Req, answering for the
bridge Domains (as returned by `normalize_domains/1`).
""".
-spec build_response(#dns_rec{}, #dns_query{}, [binary(), ...]) -> #dns_rec{}.
build_response(Req, #dns_query{domain = Domain, type = Type}, Domains) ->
    Name = mdns_proto:normalize_wire_name(Domain),
    case lists:member(Type, ?SUPPORTED_TYPES) andalso bridge_domain(Name, Domains) of
        {value, BridgeDomain} ->
            answer_record(Req, Name, Type, BridgeDomain);
        false ->
            %% Not a query in our domains of a type we understand: we have no
            %% opinion on it. NOERROR with no answers (rather than
            %% NXDOMAIN or REFUSED) is what lets a caller with
            %% alt_nameservers configured fall through to a real resolver
            %% for it - see the module doc.
            mdns_proto:dns_response(Req, [], Type, true)
    end.

bridge_domain(Name, Domains) ->
    lists:search(fun(Domain) -> mdns_proto:in_domain(Name, Domain) end, Domains).

answer_record(Req, Name, Type, Domain) ->
    Timeout = application:get_env(mdns_bridge, query_timeout_ms, ?DEFAULT_QUERY_TIMEOUT_MS),
    AnswerTtlCap = application:get_env(mdns_bridge, answer_ttl, ?DEFAULT_ANSWER_TTL),
    MdnsName = mdns_proto:replace_domain(Name, Domain, ~"local"),
    Answers =
        case mdns_query:resolve(MdnsName, Type, Timeout) of
            {ok, Found} ->
                %% The generator pattern drops any answer to_bridge_data/3
                %% couldn't rewrite.
                [
                    {Data, min(Ttl, AnswerTtlCap)}
                 || {Data0, Ttl} <- Found, {ok, Data} <- [to_bridge_data(Type, Data0, Domain)]
                ];
            {error, timeout} ->
                []
        end,
    mdns_proto:dns_response(Req, Answers, Type, Answers =/= []).

%% Rewrite `.local` names inside an answer's data into Domain, so a
%% client following a PTR or SRV target asks us about a name in the
%% domain it already routes here. A rewritten name can outgrow DNS's
%% length limits (Domain longer than "local"), and would then make
%% inet_dns:encode/2 raise - such an answer is dropped instead.
to_bridge_data(_Type, Data, ~"local") ->
    {ok, Data};
to_bridge_data(ptr, Target, Domain) ->
    to_bridge_name(Target, Domain);
to_bridge_data(srv, {Prio, Weight, Port, Target0}, Domain) ->
    case to_bridge_name(Target0, Domain) of
        {ok, Target} -> {ok, {Prio, Weight, Port, Target}};
        error -> error
    end;
to_bridge_data(_Type, Data, _Domain) ->
    {ok, Data}.

to_bridge_name(Name0, Domain) ->
    case mdns_proto:is_local(Name0) of
        true ->
            Name = mdns_proto:replace_domain(Name0, ~"local", Domain),
            case mdns_proto:validate_name(Name) of
                ok -> {ok, Name};
                {error, _} -> error
            end;
        false ->
            {ok, Name0}
    end.

reply(Socket, SrcIp, SrcPort, Response) ->
    Packet = inet_dns:encode(Response, false),
    gen_udp:send(Socket, SrcIp, SrcPort, Packet).
