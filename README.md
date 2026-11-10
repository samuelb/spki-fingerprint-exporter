# SPKI fingerprint exporter

A Prometheus exporter that connects to TLS services and reports the SHA-256
fingerprint of the public key (the *Subject Public Key Info*, SPKI) in the
certificate each service presents. Use it to alert when a service starts
presenting a key you did not expect, for example:

- a certificate was replaced outside your normal process, or a load balancer
  serves the wrong certificate;
- a TLS-intercepting proxy or man-in-the-middle sits in the path;
- clients that pin the public key (mobile apps, `curl --pinnedpubkey`,
  service-to-service pinning) are about to break because the key rotated.

> [!NOTE]
> Previously named
> [`ssl-pubkey-fingerprint-exporter`](https://github.com/samuelb/ssl-pubkey-fingerprint-exporter).
> GitHub redirects old links. The `basa/ssl-pubkey-fingerprint-exporter`
> Docker image alias is no longer updated; use
> `basa/spki-fingerprint-exporter` instead.

## How it works

The exporter works like the
[blackbox exporter](https://github.com/prometheus/blackbox_exporter): Prometheus
calls `/probe?target=<target>`, and the exporter probes that target and returns
the result as metrics. For each probe it:

1. turns the target into `host:port` (see [Targets](#targets));
2. opens a TCP connection and performs a TLS handshake, sending the hostname
   as SNI;
3. takes the public key of the leaf certificate (the first one the server
   sends), DER-encodes it as SPKI, hashes it with SHA-256 and base64-encodes
   the hash;
4. returns that value in the `fingerprint` label of the `spki_fingerprint`
   metric, along with `probe_success` and `probe_duration_seconds`.

Every probe opens a new connection, and the exporter stores nothing.
Prometheus keeps the history, and your alert rules decide which changes
matter.

The fingerprint has the same format as HPKP `pin-sha256` values, curl's
`--pinnedpubkey sha256//…` and the SPKI pins used by OkHttp and Android, so
you can compare it directly with pins you already have.

**Why fingerprint the key, not the certificate?** A certificate changes on
every renewal. The SPKI changes only when the key pair changes, so renewals
that keep the key do not trigger alerts. Many ACME setups create a new key on
every renewal (for example certbot without `--reuse-key`, or cert-manager with
`rotationPolicy: Always`). With such a setup, expect the fingerprint to change
with each renewal.

**What it does not check:** the exporter does not validate the certificate
chain, trust, hostname or expiry. Self-signed and internal certificates are
probed like any other. If you need those checks, run the blackbox exporter
(`probe_ssl_earliest_cert_expiry`) alongside this one.

## Quick start

```console
$ docker run -d --rm --name spki-exporter -p 3000:3000 basa/spki-fingerprint-exporter
$ curl -s "http://localhost:3000/probe?target=example.com:443" | grep -v '^#'
probe_duration_seconds 0.042
probe_success 1
spki_fingerprint{fingerprint="base64encodedsha256sumofspki=",target="example.com:443"} 1
```

Then [point Prometheus at it](#prometheus) and add
[alert rules](#alerting).

## Installation

**Docker:** multi-arch images (`linux/amd64`, `linux/arm64`) are published
to Docker Hub as `basa/spki-fingerprint-exporter` and to GitHub Container
Registry as `ghcr.io/samuelb/spki-fingerprint-exporter`. Tags are the release
version (for example `0.7.2`) and `latest`. Set the
[configuration](#configuration) with `-e`:

```bash
docker run -d -p 3000:3000 -e LOG_FORMAT=json basa/spki-fingerprint-exporter
```

**Helm:** the chart deploys the exporter. With the
[Prometheus Operator](https://prometheus-operator.dev/), it can also create a
ServiceMonitor for your targets and a PrometheusRule with default alerts:

```bash
helm install spki-fingerprint-exporter oci://ghcr.io/samuelb/charts/spki-fingerprint-exporter \
  --set serviceMonitor.enabled=true \
  --set-string 'serviceMonitor.targets[0]=example.com:443' \
  --set prometheusRule.enabled=true
```

Pass exporter settings through the chart's `env` value. See the
[chart README](helm/README.md) for all values.

**Binaries:** every [GitHub release](https://github.com/samuelb/spki-fingerprint-exporter/releases)
includes static binaries for Linux, macOS, Windows (`.exe`), NetBSD and
OpenBSD, the packaged Helm chart, and a `sha256sums.txt`.

**From source:** run `make build` (requires Go, see `go.mod`). The binary is
written to `dist/`.

**Verifying signatures:** container images and the Helm chart are signed
with [cosign](https://github.com/sigstore/cosign) (keyless, GitHub OIDC). The
images also carry SLSA provenance and SBOM attestations.

```bash
cosign verify --new-bundle-format=false \
  --certificate-identity-regexp '^https://github.com/samuelb/spki-fingerprint-exporter/\.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/samuelb/spki-fingerprint-exporter:latest
```

## Configuration

All configuration is through environment variables; the exporter has no
command-line flags. If a value is invalid, the exporter exits at startup with
an error.

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDRESS` | Address and port to listen on, e.g. `127.0.0.1:9000`. `:3000` listens on all interfaces | `:3000` |
| `DEFAULT_TIMEOUT` | Probe timeout for requests that do not come from Prometheus (see below). Integer seconds or a Go duration (`750ms`, `15s`) | `10` |
| `MAX_CONCURRENT_PROBES` | Maximum number of probes running at the same time. Requests beyond the limit get HTTP 503 | `64` |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error`. Failed probes are logged at `warn` with the reason; successful probes, and probes whose caller disconnected, at `debug` | `info` |
| `LOG_FORMAT` | `text` or `json` (logs go to stderr) | `text` |
| `WEB_CONFIG_FILE` | Path to an [exporter-toolkit web config](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) that enables TLS and/or basic auth on the exporter's own listener | unset |

### Probe timeout

Prometheus sends its scrape timeout with every scrape. The exporter uses that
value minus 0.5 s, which leaves time to return `probe_success 0` before
Prometheus gives up. To change the probe timeout, set `scrape_timeout` in
Prometheus. `DEFAULT_TIMEOUT` applies only to requests without that header,
such as a manual `curl`.

### TLS and basic auth

`WEB_CONFIG_FILE` uses the same file format as Prometheus and the other
official exporters, for example:

```yaml
tls_server_config:
  cert_file: /etc/spki-exporter/tls.crt
  key_file: /etc/spki-exporter/tls.key
basic_auth_users:
  # bcrypt hash, e.g. from: htpasswd -nBC 10 "" | tr -d ':\n'
  prometheus: $2y$10$...
```

When basic auth is enabled, it applies to every endpoint, including the
health checks.

## Targets

Pass `target` as `host:port` or as a URL:

| Target | Connects to |
|--------|-------------|
| `example.com:443` | `example.com:443` |
| `[2001:db8::1]:8443` | `[2001:db8::1]:8443` |
| `https://example.org` | `example.org:443` (port from the scheme) |
| `ldaps://ldap.example.com:3269` | `ldap.example.com:3269` (an explicit port takes precedence) |

The URL scheme only selects the default port; the path and query are
ignored. Schemes with a default port: `https` (443), `smtps` and
`submissions` (465), `nntps` (563), `ldaps` (636), `domain-s` (853), `ftps`
(990), `imaps` (993), `pop3s` (995), `sips` (5061). For any other scheme,
give the port explicitly.

Things to keep in mind:

- The server must start TLS as soon as the connection opens (implicit TLS).
  STARTTLS services (SMTP on 25/587, IMAP on 143, plain LDAP on 389,
  PostgreSQL, …) are not supported.
- The exporter uses Go's default TLS client settings, so the server must
  support TLS 1.2 or newer.
- The target's hostname is sent as SNI. Targets given as IP addresses are
  probed without SNI, so a server that hosts several certificates returns
  its default one.
- If a hostname resolves to several servers that use different keys, each
  probe can see a different fingerprint.

## Endpoints and metrics

| Endpoint | Purpose |
|----------|---------|
| `/probe?target=<target>` | Probes one target and returns the probe metrics |
| `/metrics` | The exporter's own operational metrics, plus Go runtime and process metrics |
| `/-/healthy`, `/-/ready` | Return HTTP 200 while the process is running |
| `/` | Landing page with the version and links |

### Probe metrics (`/probe`)

| Metric | Description |
|--------|-------------|
| `spki_fingerprint{fingerprint, target}` | Always `1`. `fingerprint` is the base64 SHA-256 of the leaf certificate's SPKI, and `target` is the target as `host:port`. Only present if the probe succeeded |
| `probe_success` | `1` if the probe succeeded. `0` if the target was invalid or unreachable, or the TLS handshake failed |
| `probe_duration_seconds` | How long the probe took |

With the scrape config below, the Prometheus `instance` label holds the
target exactly as you configured it (`https://example.org`), while the
`target` label holds it as `host:port` (`example.org:443`).

`/probe` returns HTTP 400 if `target` is missing, and HTTP 503 if
`MAX_CONCURRENT_PROBES` is reached. Prometheus records a 503 as a failed
scrape (`up == 0`), not as `probe_success 0`.

### Operational metrics (`/metrics`)

| Metric | Description |
|--------|-------------|
| `spki_fingerprint_exporter_active_probes` | Probes currently running |
| `spki_fingerprint_exporter_probes_total{result="success\|failure"}` | Completed probes, by result |
| `spki_fingerprint_exporter_rejected_probes_total` | Probes rejected with HTTP 503 because of `MAX_CONCURRENT_PROBES` |
| `spki_fingerprint_exporter_build_info` | Version and build metadata |

## Prometheus

List your TLS services as targets. The relabeling sends each one to the
exporter as the `target` parameter and keeps it as the `instance` label:

```yaml
scrape_configs:
  - job_name: "spki-fingerprint-exporter"
    metrics_path: /probe
    scrape_timeout: 10s # also the probe timeout, see "Probe timeout"
    static_configs:
      - targets:
          - example.com:443
          - https://example.org
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: spki-fingerprint-exporter:3000 # the exporter's address
```

To collect the operational metrics, add a second job that scrapes
`spki-fingerprint-exporter:3000` with the default `/metrics` path.

### Alerting

There are two ways to alert, and you can combine them:

- **Pinning:** you know the expected fingerprint (see
  [below](#getting-the-expected-fingerprint)) and alert when a target
  presents a different one.
- **Change detection:** you do not track the expected values and alert
  whenever a target's fingerprint changes.

```yaml
groups:
  - name: spki-fingerprint
    rules:
      # Pinning: example.com:443 presents a key other than the expected
      # one. Requiring probe_success == 1 keeps a failing probe from also
      # firing this alert.
      - alert: SpkiFingerprintMismatch
        expr: |
          probe_success{job="spki-fingerprint-exporter", instance="example.com:443"} == 1
          unless on(instance)
          spki_fingerprint{fingerprint="base64encodedsha256sumofspki="}

      # Change detection: a target presented more than one distinct
      # fingerprint within the last hour.
      - alert: SpkiFingerprintChanged
        expr: |
          count by (target) (
            count by (target, fingerprint) (count_over_time(spki_fingerprint[1h]))
          ) > 1

      # The target is unreachable or the TLS handshake fails.
      - alert: SpkiProbeFailed
        expr: probe_success{job="spki-fingerprint-exporter"} == 0
        for: 5m
```

Scope `probe_success` by `job` as shown: other blackbox-style exporters
export the same metric name.

## Getting the expected fingerprint

The easiest way is to probe the service with the exporter and copy the
`fingerprint` label. To compute it with `openssl`:

From a certificate (PEM):

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

From a private key or CSR, which is useful for pinning a key before it is
deployed (works for RSA, ECDSA and Ed25519 keys):

```sh
openssl pkey -in key.pem -pubout -outform der | openssl dgst -sha256 -binary | openssl enc -base64
openssl req -in csr.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

From a running server:

```sh
host=example.com; openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

## Security considerations

`/probe` opens a TLS connection to any `host:port` a caller supplies, as is
common for blackbox-style exporters. Anyone who can reach the exporter can
make it connect to hosts on its network. Do not expose it to untrusted
networks, and allow access only from your Prometheus servers: use network
rules, the Helm chart's `networkPolicy`, or basic auth through
[`WEB_CONFIG_FILE`](#tls-and-basic-auth).

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the
[Apache License 2.0](LICENSE).
