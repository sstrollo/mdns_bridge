-module(mdns_iface_tests).

-include_lib("eunit/include/eunit.hrl").

same_subnet_test_() ->
    [
        ?_assert(
            mdns_iface:same_subnet({192, 168, 1, 42}, {192, 168, 1, 1}, {255, 255, 255, 0})
        ),
        ?_assertNot(
            mdns_iface:same_subnet({192, 168, 2, 42}, {192, 168, 1, 1}, {255, 255, 255, 0})
        ),
        ?_assert(
            mdns_iface:same_subnet({10, 0, 0, 1}, {10, 0, 0, 1}, {255, 255, 255, 255})
        ),
        ?_assertNot(
            mdns_iface:same_subnet({10, 0, 0, 2}, {10, 0, 0, 1}, {255, 255, 255, 255})
        ),
        ?_assert(
            %% /16
            mdns_iface:same_subnet({172, 16, 200, 5}, {172, 16, 0, 1}, {255, 255, 0, 0})
        )
    ].
