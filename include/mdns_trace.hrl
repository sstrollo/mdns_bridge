%% Traces Kind/Info via mdns_trace:event/2 - but only constructs Info at
%% all when tracing is actually enabled. This works because a macro
%% argument is plain text substitution, not an eagerly-evaluated
%% expression: Info is written inline inside the `true' branch below, so
%% it's only ever evaluated when that branch is the one taken - the same
%% trick logger's own ?LOG_DEBUG-style macros use to avoid formatting a
%% report nobody will see. mdns_trace:enabled/0 is a cheap persistent_term
%% read, safe to call on every event site regardless of how hot it is.
-define(TRACE(Kind, Info),
    case mdns_trace:enabled() of
        true -> mdns_trace:event((Kind), (Info));
        false -> ok
    end
).
