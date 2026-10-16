---
icon: material/new-box
---

!!! quote "Changes in sing-box 1.15.0"

    :material-plus: [certificate_sha256](#certificate_sha256)  
    :material-plus: [client_certificate_sha256](#client_certificate_sha256)

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [certificate_provider](#certificate_provider)  
    :material-plus: [handshake_timeout](#handshake_timeout)  
    :material-plus: [spoof](#spoof)  
    :material-plus: [spoof_method](#spoof_method)  
    :material-plus: [engine](#engine)  
    :material-delete-clock: [acme](#acme-fields)

!!! quote "Changes in sing-box 1.13.0"

    :material-plus: [kernel_tx](#kernel_tx)  
    :material-plus: [kernel_rx](#kernel_rx)  
    :material-plus: [curve_preferences](#curve_preferences)  
    :material-plus: [certificate_public_key_sha256](#certificate_public_key_sha256)  
    :material-plus: [client_certificate](#client_certificate)  
    :material-plus: [client_certificate_path](#client_certificate_path)  
    :material-plus: [client_key](#client_key)  
    :material-plus: [client_key_path](#client_key_path)  
    :material-plus: [client_authentication](#client_authentication)  
    :material-plus: [client_certificate_public_key_sha256](#client_certificate_public_key_sha256)  
    :material-plus: [ech.query_server_name](#query_server_name)

!!! quote "Changes in sing-box 1.12.0"

    :material-plus: [fragment](#fragment)  
    :material-plus: [fragment_fallback_delay](#fragment_fallback_delay)  
    :material-plus: [record_fragment](#record_fragment)  
    :material-delete-clock: [ech.pq_signature_schemes_enabled](#pq_signature_schemes_enabled)  
    :material-delete-clock: [ech.dynamic_record_sizing_disabled](#dynamic_record_sizing_disabled)

!!! quote "Changes in sing-box 1.10.0"

    :material-alert-decagram: [utls](#utls)

### Inbound

```json
{
  "enabled": true,
  "server_name": "",
  "alpn": [],
  "min_version": "",
  "max_version": "",
  "cipher_suites": [],
  "curve_preferences": [],
  "certificate": [],
  "certificate_path": "",
  "client_authentication": "",
  "client_certificate": [],
  "client_certificate_path": [],
  "client_certificate_sha256": [],
  "client_certificate_public_key_sha256": [],
  "key": [],
  "key_path": "",
  "kernel_tx": false,
  "kernel_rx": false,
  "handshake_timeout": "",
  "certificate_provider": "",

  // Deprecated

  "acme": {
    "domain": [],
    "data_directory": "",
    "default_server_name": "",
    "email": "",
    "provider": "",
    "disable_http_challenge": false,
    "disable_tls_alpn_challenge": false,
    "alternative_http_port": 0,
    "alternative_tls_port": 0,
    "external_account": {
      "key_id": "",
      "mac_key": ""
    },
    "dns01_challenge": {}
  },
  "ech": {
    "enabled": false,
    "key": [],
    "key_path": "",

    // Deprecated
    
    "pq_signature_schemes_enabled": false,
    "dynamic_record_sizing_disabled": false
  },
  "reality": {
    "enabled": false,
    "handshake": {
      "server": "google.com",
      "server_port": 443,

      ... // Dial Fields
    },
    "private_key": "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
    "short_id": [
      "0123456789abcdef"
    ],
    "max_time_difference": "1m"
  }
}
```

### Outbound

```json
{
  "enabled": true,
  "engine": "",
  "disable_sni": false,
  "server_name": "",
  "insecure": false,
  "alpn": [],
  "min_version": "",
  "max_version": "",
  "cipher_suites": [],
  "curve_preferences": [],
  "certificate": "",
  "certificate_path": "",
  "certificate_sha256": [],
  "certificate_public_key_sha256": [],
  "client_certificate": [],
  "client_certificate_path": "",
  "client_key": [],
  "client_key_path": "",
  "fragment": false,
  "fragment_fallback_delay": "",
  "record_fragment": false,
  "spoof": "",
  "spoof_method": "",
  "kernel_tx": false,
  "kernel_rx": false,
  "handshake_timeout": "",
  "ech": {
    "enabled": false,
    "config": [],
    "config_path": "",
    "query_server_name": "",

    // Deprecated
    "pq_signature_schemes_enabled": false,
    "dynamic_record_sizing_disabled": false
  },
  "utls": {
    "enabled": false,
    "fingerprint": ""
  },
  "reality": {
    "enabled": false,
    "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
    "short_id": "0123456789abcdef"
  }
}
```

TLS version values:

* `1.0`
* `1.1`
* `1.2`
* `1.3`

Cipher suite values:

* `TLS_RSA_WITH_AES_128_CBC_SHA`
* `TLS_RSA_WITH_AES_256_CBC_SHA`
* `TLS_RSA_WITH_AES_128_GCM_SHA256`
* `TLS_RSA_WITH_AES_256_GCM_SHA384`
* `TLS_AES_128_GCM_SHA256`
* `TLS_AES_256_GCM_SHA384`
* `TLS_CHACHA20_POLY1305_SHA256`
* `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
* `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
* `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`
* `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`
* `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
* `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
* `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### enabled

Enable TLS.

#### engine

!!! question "Since sing-box 1.14.0"

==Client only==

TLS engine to use.

Values:

* `go` (default)
* `apple`
* `windows`

Supported fields:

* `server_name`
* `insecure`
* `alpn`
* `min_version`
* `max_version`
* `certificate` / `certificate_path`
* `certificate_sha256`
* `certificate_public_key_sha256`
* `handshake_timeout`

Unsupported fields:

* `disable_sni`
* `cipher_suites`
* `curve_preferences`
* `client_certificate` / `client_certificate_path` / `client_key` / `client_key_path`
* `fragment` / `record_fragment`
* `kernel_tx` / `kernel_rx`
* `ech`
* `utls`
* `reality`

!!! note ""

    `windows` uses Schannel via SSPI. Only available on Windows build 17763 or later (Windows 10 version 1809, Windows Server 2019, or newer).

!!! note ""

    TLS 1.3 is only negotiated on Windows 11 or Windows Server 2022 and newer.

The default version range is TLS 1.2 to TLS 1.3, matching the `go` engine.

#### disable_sni

==Client only==

Do not send server name in ClientHello.

#### server_name

Used to verify the hostname on the returned certificates unless insecure is given.

It is also included in the client's handshake to support virtual hosting unless it is an IP address.

#### insecure

==Client only==

Accepts any server certificate.

#### alpn

List of supported application level protocols, in order of preference.

If both peers support ALPN, the selected protocol will be one from this list, and the connection will fail if there is
no mutually supported protocol.

See [Application-Layer Protocol Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).

With REALITY, an explicit client list is preserved in the authenticated
ClientHello. This fork's REALITY server selects from its own `alpn` list and
rejects disjoint lists, independently of the camouflage server's ALPN policy.
Camouflage record sizes remain padding targets when the actual encrypted
extensions fit. A larger negotiated extension uses its own minimum valid TLS
record rather than negative padding or truncation; exact camouflage record
length is therefore not promised for a different ALPN policy. Other handshake
record budgets retain their existing checks.
Use the completed connection's `NegotiatedProtocol` as evidence; a ClientHello
offer or the camouflage site's configuration is not a negotiated protocol.
Older remote REALITY servers may omit ALPN even when the client offers it. HTTP/2
callers must continue to require an actual `h2` negotiation.


#### min_version

The minimum TLS version that is acceptable.

TLS 1.2 is used by default.

#### max_version

The maximum TLS version that is acceptable.

By default, the maximum version is currently TLS 1.3.

#### cipher_suites

List of enabled TLS 1.0–1.2 cipher suites. The order of the list is ignored.
Note that TLS 1.3 cipher suites are not configurable.

If empty, a safe default list is used. The default cipher suites might change over time.

#### curve_preferences

!!! question "Since sing-box 1.13.0"

Set of supported key exchange mechanisms. The order of the list is ignored, and key exchange mechanisms are chosen
from this list using an internal preference order by Golang.

Available values, also the default list:

* `P256`
* `P384`
* `P521`
* `X25519`
* `X25519MLKEM768`

#### certificate

Server certificates chain line array, in PEM format.

#### certificate_path

!!! note ""

    Will be automatically reloaded if file modified.

The path to server certificate chain, in PEM format.


#### certificate_sha256

!!! question "Since sing-box 1.15.0"

==Client only==

List of SHA-256 hashes of server certificates, in base64 format.

The hash is computed over the whole DER-encoded certificate. Use `certificate_public_key_sha256` to pin only the public key.

To generate the SHA-256 hash for a certificate, use the following commands:

```bash
# For a certificate file
openssl x509 -in certificate.pem -outform der | openssl dgst -sha256 -binary | openssl enc -base64

# For a certificate from a remote server
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

#### certificate_public_key_sha256

!!! question "Since sing-box 1.13.0"

==Client only==

List of SHA-256 hashes of server certificate public keys, in base64 format.

To generate the SHA-256 hash for a certificate's public key, use the following commands:

```bash
# For a certificate file
openssl x509 -in certificate.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

# For a certificate from a remote server
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

#### client_certificate

!!! question "Since sing-box 1.13.0"

==Client only==

Client certificate chain line array, in PEM format.

#### client_certificate_path

!!! question "Since sing-box 1.13.0"

==Client only==

The path to client certificate chain, in PEM format.

#### client_key

!!! question "Since sing-box 1.13.0"

==Client only==

Client private key line array, in PEM format.

#### client_key_path

!!! question "Since sing-box 1.13.0"

==Client only==

The path to client private key, in PEM format.

#### key

==Server only==

The server private key line array, in PEM format.

#### key_path

==Server only==

!!! note ""

    Will be automatically reloaded if file modified.

The path to the server private key, in PEM format.

#### client_authentication

!!! question "Since sing-box 1.13.0"

==Server only==

The type of client authentication to use.

Available values:

* `no` (default)
* `request`
* `require-any`
* `verify-if-given`
* `require-and-verify`

One of `client_certificate`, `client_certificate_path`, `client_certificate_sha256`, or `client_certificate_public_key_sha256` is required
if this option is set to `verify-if-given`, or `require-and-verify`.

#### client_certificate

!!! question "Since sing-box 1.13.0"

==Server only==

Client certificate chain line array, in PEM format.

#### client_certificate_path

!!! question "Since sing-box 1.13.0"

==Server only==

!!! note ""

    Will be automatically reloaded if file modified.

List of path to client certificate chain, in PEM format.

#### client_certificate_sha256

!!! question "Since sing-box 1.15.0"

==Server only==

List of SHA-256 hashes of client certificates, in base64 format.

The hash is computed over the whole DER-encoded certificate, see [certificate_sha256](#certificate_sha256).

#### client_certificate_public_key_sha256

!!! question "Since sing-box 1.13.0"

==Server only==

List of SHA-256 hashes of client certificate public keys, in base64 format.

To generate the SHA-256 hash for a certificate's public key, use the following commands:

```bash
# For a certificate file
openssl x509 -in certificate.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

# For a certificate from a remote server
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

#### kernel_tx

!!! question "Since sing-box 1.13.0"

!!! quote ""

    Only supported on Linux 5.1+, use a newer kernel if possible.

!!! quote ""

    Only TLS 1.3 is supported.

!!! warning ""

    kTLS TX may only improve performance when `splice(2)` is available (both ends must be TCP or TLS without additional protocols after handshake); otherwise, it will definitely degrade performance.

Enable kernel TLS transmit support.

#### kernel_rx

!!! question "Since sing-box 1.13.0"

!!! quote ""

    Only supported on Linux 5.1+, use a newer kernel if possible.

!!! quote ""

    Only TLS 1.3 is supported.

!!! failure ""

    kTLS RX will definitely degrade performance even if `splice(2)` is in use, so enabling it is not recommended.

Enable kernel TLS receive support.

#### handshake_timeout

!!! question "Since sing-box 1.14.0"

TLS handshake timeout, in golang's Duration format.

`15s` is used by default.

#### certificate_provider

!!! question "Since sing-box 1.14.0"

==Server only==

A string or an object.

When string, the tag of a shared [Certificate Provider](/configuration/shared/certificate-provider/).

When object, an inline certificate provider. See [Certificate Provider](/configuration/shared/certificate-provider/) for available types and fields.

## Custom TLS support

!!! info "QUIC support"

    Only ECH is supported in QUIC.

#### utls

==Client only==

!!! failure "Not Recommended"

    uTLS has had repeated fingerprinting vulnerabilities discovered by researchers.

    uTLS is a Go library that attempts to imitate browser TLS fingerprints by copying
    ClientHello structure. However, browsers use completely different TLS stacks
    (Chrome uses BoringSSL, Firefox uses NSS) with distinct implementation behaviors
    that cannot be replicated by simply copying the handshake format, making detection possible.
    Additionally, the library lacks active maintenance and has poor code quality,
    making it unsuitable for censorship circumvention.

    For TLS fingerprint resistance, use [NaiveProxy](/configuration/inbound/naive/) instead.

uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting resistance.

Available fingerprint values:

!!! warning "Removed since sing-box 1.10.0"

    Some legacy chrome fingerprints have been removed and will fallback to chrome:

    :material-close: chrome_psk  
    :material-close: chrome_psk_shuffle  
    :material-close: chrome_padding_psk_shuffle  
    :material-close: chrome_pq  
    :material-close: chrome_pq_psk

* chrome
* firefox
* edge
* safari
* 360
* qq
* ios
* android
* random
* randomized

Chrome fingerprint will be used if empty.

### Runtime fingerprint capabilities

Query the exact selected executable with `sing-box tools tls-fingerprints`.
Mobile callers use `libbox.TLSFingerprintCapabilities()` on the library actually
loaded by the process. Both return `polaris-tls-fingerprint-capabilities-v1` JSON.
A packaged version string does not identify the running helper or loaded library.

The `profiles` array supplies accepted JSON `id`, `displayName`, actual template
`client` and `templateVersion`, `selection`, and nullable
`templateOffersX25519MLKEM768`. In this source revision the browser mappings are:

| JSON ID | Template |
| --- | --- |
| `chrome`, `chrome_155` | Chrome 155 |
| `chrome_133` | Chrome 133 |
| `firefox`, `firefox_148` | Firefox 148 |
| `firefox_120` | Firefox 120 |
| `safari`, `safari_26_3` | Safari 26.3 |
| `safari_16_0` | Safari 16.0 |
| `edge` | Edge 85 |
| `360` | 360 7.5 |
| `qq` | QQ 11.1 |
| `ios` | iOS 14 |
| `android` | Android 11 OkHttp |

These version labels identify the pinned library templates, not a guarantee that
all browser behavior is reproduced. Auto aliases can change with a future core;
read the selected core's response rather than assuming this table applies to it.
The five `legacyChromeAliases` still select Chrome Auto. Explicit Safari 15.3/15.5
IDs do not exist. `random` selects one browser Auto template per process; restarting
a libbox service within that process does not reselect it. Query again after a
process restart; do not persist the concrete random draw across processes. Its response records
the selected template. `randomized` uses a process-scoped seeded generator, not
a browser draw, and does not guarantee a different fingerprint per connection.

An empty fingerprint selects `defaultFingerprint` (`chrome`). `default`,
`disabled`, `none`, and `follow` are not fingerprint IDs: a caller implementing
those preferences must resolve them before serialization. Disable uTLS with
`utls.enabled=false`; default uTLS uses `enabled=true` and an omitted fingerprint.
Without the `with_utls` build tag, `enabled=false` and `profiles` is empty.

The same response includes `coreVersion`, `sourceCommit`, nullable
`sourceModified`, actual runtime `goVersion`, informational `requiredGoVersion`,
`buildTags`, `os`, `arch`, and linked uTLS `modules` with version, h1 sum and any
replacement. The Meta v1.8.8 REALITY ALPN compatibility code is a source-owned
`./third_party/metacubex-utls` replacement. Its linked `sum` is empty and the
replacement is reported as `(devel)`; the original upstream h1 describes only
the immutable baseline, not these modified bytes. Bind the replacement to the
producer's exact source commit/tree and local replacement tree, with baseline
and explicit two-file production delta (`reality.go`/`conn.go`) in `release/dependency-sources/metacubex-utls-replacement.json`.
Clean producers stamp the source commit even with `-trimpath` or
`-buildvcs=false`; conflicting stamps are errors. Unavailable build metadata stays
empty/null rather than being inferred from the version. Some mobile linkers omit
module metadata. The response is a capability description, not a signature or a
hash of its own executable. Bind it to the actual core file SHA-256 (or loaded
mobile artifact identity), checked producer source/build receipts and actual
BuildID. Cache by that selected artifact identity, and invalidate on a helper,
source, library, or build change. Missing or unsupported queries on upstream,
testing or custom old cores do not prove this fork's capabilities.

A template offer is distinct from a negotiated connection. Chrome 155 advertises
ML-DSA signature algorithms and Trust Anchors; this is not proof of an ML-DSA
certificate or successful PQ authentication. Ordinary TLS may negotiate
X25519MLKEM768 with a supporting peer. REALITY authentication remains classical:
X25519MLKEM768 is removed from both supported groups and key shares. The response
reports these boundaries; it does not claim a successful handshake.
`curve_preferences` with uTLS is rejected because the selected template owns its
groups. ShadowTLS v3 session-ID authentication together with real ECH is explicitly
rejected; ordinary ECH remains a separate supported path requiring peer support.

The pinned gomobile v0.1.13 generator maps the mobile query to Java
`Libbox.tlsFingerprintCapabilities()` (String, throws Exception) and the ObjC
function `LibboxTLSFingerprintCapabilities(NSError **error)` (NSString pointer).
The generator annotates the string `_Nonnull` but its error path returns nil;
check the error and returned object. A generated declaration is not proof that
an old loaded library contains the symbol. Resolve/query the loaded library
without inferring availability from a version; missing symbols mean unavailable
capabilities. The producer checks the actual generated headers, static exports
and Java declaration, while final App linkage/loading is a separate observation.


This migration's controlled regression covers ordinary TLS records and the
owning-library TLS 1.3 traffic-secret/key derivation for std TLS, Meta and
refraction. It does not establish a peer KeyUpdate exchange, kernel offload key
reinstallation or complete kTLS runtime acceptance. Those paths need their actual
platform observations before such an acceptance claim.

### ECH Fields

ECH (Encrypted Client Hello) is a TLS extension that allows a client to encrypt the first part of its ClientHello
message.

The ECH key and configuration can be generated by `sing-box generate ech-keypair`.

#### pq_signature_schemes_enabled

!!! failure "Deprecated in sing-box 1.12.0"

    `pq_signature_schemes_enabled` is deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0.

Enable support for post-quantum peer certificate signature schemes.

#### dynamic_record_sizing_disabled

!!! failure "Deprecated in sing-box 1.12.0"

    `dynamic_record_sizing_disabled` is deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0.

Disables adaptive sizing of TLS records.

When true, the largest possible TLS record size is always used.  
When false, the size of TLS records may be adjusted in an attempt to improve latency.

#### key

==Server only==

ECH key line array, in PEM format.

#### key_path

==Server only==

!!! note ""

    Will be automatically reloaded if file modified.

The path to ECH key, in PEM format.

#### config

==Client only==

ECH configuration line array, in PEM format.

If empty, load from DNS will be attempted.

#### config_path

==Client only==

The path to ECH configuration, in PEM format.

If empty, load from DNS will be attempted.

#### query_server_name

!!! question "Since sing-box 1.13.0"

==Client only==

Overrides the domain name used for ECH HTTPS record queries.

If empty, `server_name` is used for queries.

#### fragment

!!! question "Since sing-box 1.12.0"

==Client only==

Fragment TLS handshakes to bypass firewalls.

This feature is intended to circumvent simple firewalls based on **plaintext packet matching**,
and should not be used to circumvent real censorship.

Due to poor performance, try `record_fragment` first, and only apply to server names known to be blocked.

On Linux, Apple platforms, (administrator privileges required) Windows,
the wait time can be automatically detected. Otherwise, it will fall back to
waiting for a fixed time specified by `fragment_fallback_delay`.

In addition, if the actual wait time is less than 20ms, it will also fall back to waiting for a fixed time,
because the target is considered to be local or behind a transparent proxy.

#### fragment_fallback_delay

!!! question "Since sing-box 1.12.0"

==Client only==

The fallback value used when TLS segmentation cannot automatically determine the wait time.

`500ms` is used by default.

#### record_fragment

!!! question "Since sing-box 1.12.0"

==Client only==

Fragment TLS handshake into multiple TLS records to bypass firewalls.

#### spoof

!!! question "Since sing-box 1.14.0"

==Client only==

!!! quote ""

    Only supported on Linux, macOS, and Windows, and requires elevated privileges.

Inject a forged TLS ClientHello carrying a whitelisted SNI before the real one,
to fool SNI-filtering middleboxes that permit specific hostnames.

Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` on Linux, root on macOS, and
Administrator on Windows. Windows on ARM64 is not supported.

#### spoof_method

!!! question "Since sing-box 1.14.0"

==Client only==

How the forged segment is rejected by the real server.

| Value                      | Behavior                                                                                                       |
|----------------------------|----------------------------------------------------------------------------------------------------------------|
| `wrong-sequence` (default) | The forged segment's TCP sequence number is placed before the server's receive window.                         |
| `wrong-checksum`           | The forged segment's TCP checksum is deliberately invalid.                                                     |
| `wrong-ack`                | The forged segment's TCP acknowledgment number is placed before the server's send window.                      |
| `wrong-md5`                | The forged segment carries a TCP-MD5 signature option.                                                         |
| `wrong-timestamp`          | The forged segment carries a backdated TCP timestamp. Linux/Windows only; not supported on macOS.              |

### ACME Fields

!!! failure "Deprecated in sing-box 1.14.0"

    Inline ACME options are deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, check [Migration](/migration/#migrate-inline-acme-to-certificate-provider).

#### domain

List of domain.

ACME will be disabled if empty.

#### data_directory

The directory to store ACME data.

`$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic` will be used if empty.

#### default_server_name

Server name to use when choosing a certificate if the ClientHello's ServerName field is empty.

#### email

The email address to use when creating or selecting an existing ACME server account

#### provider

The ACME CA provider to use.

| Value                   | Provider      |
|-------------------------|---------------|
| `letsencrypt (default)` | Let's Encrypt |
| `zerossl`               | ZeroSSL       |
| `https://...`           | Custom        |

#### disable_http_challenge

Disable all HTTP challenges.

#### disable_tls_alpn_challenge

Disable all TLS-ALPN challenges

#### alternative_http_port

The alternate port to use for the ACME HTTP challenge; if non-empty, this port will be used instead of 80 to spin up a
listener for the HTTP challenge.

#### alternative_tls_port

The alternate port to use for the ACME TLS-ALPN challenge; the system must forward 443 to this port for challenge to
succeed.

#### external_account

EAB (External Account Binding) contains information necessary to bind or map an ACME account to some other account known
by the CA.

External account bindings are "used to associate an ACME account with an existing account in a non-ACME system, such as
a CA customer database.

To enable ACME account binding, the CA operating the ACME server needs to provide the ACME client with a MAC key and a
key identifier, using some mechanism outside of ACME. §7.3.4

#### external_account.key_id

The key identifier.

#### external_account.mac_key

The MAC key.

#### dns01_challenge

ACME DNS01 challenge field. If configured, other challenge methods will be disabled.

See [DNS01 Challenge Fields](/configuration/shared/dns01_challenge/) for details.

### Reality Fields

#### handshake

==Server only==

==Required==

Handshake server address and [Dial Fields](/configuration/shared/dial/).

#### private_key

==Server only==

==Required==

Private key, generated by `sing-box generate reality-keypair`.

#### public_key

==Client only==

==Required==

Public key, generated by `sing-box generate reality-keypair`.

#### short_id

==Required==

A hexadecimal string with zero to eight digits.

#### max_time_difference

==Server only==

The maximum time difference between the server and the client.

Check disabled if empty.
