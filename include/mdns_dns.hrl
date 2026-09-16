%% Vendored copies of the record shapes produced/consumed by OTP's
%% kernel-internal inet_dns module (kernel/src/inet_dns.erl).
%%
%% inet_dns.hrl is NOT published under kernel/include (only kernel/src), so
%% it isn't includable from other applications. inet_dns itself is
%% `-moduledoc false` (unofficial API), but it's the module OTP itself uses
%% for DNS encode/decode and it already understands RFC 6762 (mDNS)
%% semantics via decode/2 and encode/2's `Mdns` flag, so we vendor the
%% record shapes here rather than reimplement wire (de)coding.
%%
%% Field names/order must stay in sync with kernel's inet_dns.hrl. Verified
%% against kernel-10.6.3.3 (OTP 28).

-record(dns_header, {
    id = 0,
    qr = 0,
    opcode = 0,
    aa = 0,
    tc = 0,
    rd = 0,
    ra = 0,
    pr = 0,
    rcode = 0
}).

-record(dns_rec, {
    header,
    qdlist = [],
    anlist = [],
    nslist = [],
    arlist = []
}).

-record(dns_query, {
    domain,
    type,
    class,
    unicast_response = false
}).

-record(dns_rr, {
    domain = "",
    type = any,
    class = in,
    cnt = 0,
    ttl = 0,
    data = [],
    tm,
    bm = "",
    %% cache-flush bit (mDNS, RFC 6762) when decoded with Mdns=true
    func = false
}).
