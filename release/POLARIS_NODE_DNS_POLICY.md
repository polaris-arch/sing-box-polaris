# Scoped native node DNS policy

This opt-in extension lets node dialers use native DNS evaluate/respond rules without
an application-resident UDP resolver. Ordinary DNS groups and unscoped resolver rules
retain their existing semantics. A compatible App and core must be delivered together;
older cores must not be given the new fields.

## Configuration contract

A node dialer selects `domain_resolver: {"mode":"rules","policy":"node-bootstrap",
"strategy":"prefer_ipv4","timeout":"2s"}`. Empty or unknown policy names fail
validation. DNS server bootstrap must remain explicit server resolution, never a
recursive node policy. DNS server candidates own physical-interface binding independently
of the eventual node socket's interface.

Top-level default DNS rules with `resolver_policy` form a separate ordered slice.
Ordinary DNS does not execute them. Policy conditions are restricted to question,
response, and immutable configuration data. Existing private-name, LAN, mDNS and mesh
protections must precede public candidates. Caller-dependent process/user/inbound or
network-interface matches are rejected because background refresh cannot reproduce them.

Each tier starts with a non-speculative `evaluate`; subsequent candidates are speculative.
All evaluated candidates require explicit tags, `disable_cache:true`,
`disable_optimistic_cache:true`, and an App-generated `timeout:"1500ms"`.
Each candidate binds two racing respond rules:

- `response_class:"hit"`, with `response_reject_ip_cidr` containing decoy prefixes;
- `response_class:"empty"`, with `mode:"defer"`.

The final unconditional rule is `action:"respond", mode:"fallback",
fallback_rcode:"SERVFAIL"`. Exactly one such final rule is required per policy.
No additional transport protocol or socket listener implements this policy.

## Response and timing semantics

HIT means a complete response (QR, no TC), NOERROR, and an IN Answer record of the
current question type. Scoped Lookup accepts only actual IN A/AAAA Answer addresses,
never HTTPS/SVCB hints or non-IN records. Raw Exchange also preserves genuine current-type
records such as HTTPS for the Naive/Cronet proxy resolver and ECH. Any rejected IN A/AAAA Answer poisons the whole HIT.
Additional-section addresses and HTTPS/SVCB hints are not HITs. NXDOMAIN is EMPTY;
a clean NOERROR without the requested family is EMPTY. For compatibility, decoy rejection
applies to HIT classification, not to otherwise EMPTY responses.

EMPTY retains the original response, authority records and transport. It never wins
against an eligible HIT or starts a later tier before the current tier drains. The
first completed EMPTY across tiers is returned only when the policy exhausts or its
own budget expires. Failure without EMPTY yields SERVFAIL, never a synthetic NOERROR.
The ready winner is chosen by callback completion sequence, rather than rule order.
Callback publication and response-metadata snapshot share a lock. At cutoff,
already-launched futures are matched even if the walker had not yet armed their
response rules; it never launches another candidate, including delayed timer delivery.

One Lookup policy budget is shared by A and AAAA. Each independent raw Exchange
request owns one budget, matching the former wire sidecar behavior; it does not
reuse the long-lived Cronet proxy context as a global deadline. Only a single IN
question is supported. Caller cancellation remains cancellation;
only the policy's own deadline permits fallback. Results completed after cutoff do not
win, and no candidate starts after cutoff. Both family query workers are joined before
Lookup returns. Upstream transports must cooperate with cancellation as usual.

## Cache and invalidation

A private, unregistered, no-socket adapter invokes the existing rule walker through
DNS Client's final-response cache and singleflight machinery. Candidate caches are off;
outer cache flags are independent. Only final eligible NOERROR/NXDOMAIN responses cache,
with existing TTL/negative-SOA requirements. SERVFAIL, cancellation and rejected
candidates are not stored.

The cache namespace fingerprints scope, ordered rules, server configuration and relevant
resolver options. Existing question/class/type/ECS keys and network epochs are retained.
Candidate transport environments and current preferred-domain eligibility also participate
in invalidation; an environment change during exchange prevents storage. Optimistic
refresh reconstructs the scope and question without retaining mutable caller metadata.
Recursive entry into the same policy is rejected before waiting on its cache lock.

## Validation

Tests cover classification, tier barriers, first EMPTY, deadline/cancellation, poison,
cache lifetime and invalidation, singleflight, ordinary-rule isolation and A-only system
candidates. Cross-repository acceptance must additionally run actual App-generated
configurations through node DialContext and ListenPacket and the platform CI matrix.
Source-level and unit tests alone do not establish release compatibility or platform PASS.
