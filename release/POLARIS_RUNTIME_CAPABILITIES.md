# Polaris daily runtime updates

The implementation manifest describes available adapters; it is not a source or
artifact signature. Consumers must verify their pinned kernel identity and query
the running instance's capabilities and plan. An eligible started instance enables
the supported daily graph updates without an opt-in switch. `FullConfiguration`
remains `false`; this is not support for arbitrary configuration replacement.

## Stable local API and dashboard

An unchanged, plain loopback API service can coexist with daily graph updates.
An enabled dashboard is supported when its HTTP client is an explicit inline
client containing only a nonempty `detour`. The referenced outbound must itself
be valid; this does not waive the empty-direct-detour check. Named/default clients,
additional HTTP client fields, TLS and unsupported listener dependencies retain
the legacy path. Non-loopback listeners are not newly admitted.

The host owns the stable API service. Each managed dashboard download borrows
the current published graph and its privately prepared HTTP transport through
redirects and response-body closure. Idle update workers do not pin an initial
graph. Closing the service cancels and joins its worker before graph drainage.
Existing user-provided static dashboard files are served without automatic
updates. Updates are limited to absent/empty directories or the existing managed
directory marked by its regular `.etag` file; archive path and ownership checks
are retained. Download or validation failures before replacement leave the current
directory unchanged. Failures while replacing an existing managed directory
attempt to restore it; if restoration fails, the backup is retained and the error
is reported. A completed replacement is not rolled back for a later response-body
close failure; that cleanup error is still reported.

Changing any service configuration still requires an explicit host restart.
The unsupported experimental Clash API external-dashboard adapter is unchanged.
Other unsupported components may also prevent initial runtime eligibility.

## Legacy HTTP consumers

Starting a legacy graph without an HTTP consumer does not select an implicit
default HTTP client. An actual consumer requesting that default still encounters
the existing deprecation policy; explicit configured defaults remain validated.
Connected runtime graphs continue to prepare and freeze their HTTP resources.

These are source-level support boundaries, not a claim that every App-generated
configuration, mobile platform or physical device has been accepted. Published
release receipts describe their own immutable source, not later source changes.
