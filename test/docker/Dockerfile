# Self-contained end-to-end test environment for the mdns app: a real
# avahi-daemon (a genuine mDNS peer) plus dig, running alongside the app
# itself, so the .local bridge can be exercised the same way `dig` would
# be used against it in production.
FROM erlang:28

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    iproute2 \
    dbus \
    avahi-daemon \
    avahi-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY rebar.config rebar.config
COPY config config
COPY include include
COPY src src
COPY test test
RUN rebar3 compile

COPY test/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY test/docker/run_e2e.sh /usr/local/bin/run_e2e.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/run_e2e.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
