# spki-fingerprint-exporter

Prometheus exporter that reports the SHA-256 fingerprint of the Subject Public
Key Info (SPKI) in certificates presented by TLS services. Use it to alert
when a service starts presenting an unexpected public key — for example after
an unnoticed certificate replacement or a man-in-the-middle.

This chart deploys the exporter and can optionally create a
[Prometheus Operator](https://prometheus-operator.dev/) ServiceMonitor that
probes a list of TLS targets.

- Project: <https://github.com/samuelb/spki-fingerprint-exporter>
- Images: `basa/spki-fingerprint-exporter` (Docker Hub) and
  `ghcr.io/samuelb/spki-fingerprint-exporter`

## Installing

```bash
helm install spki-fingerprint-exporter oci://ghcr.io/samuelb/charts/spki-fingerprint-exporter
```

To probe targets via the Prometheus Operator, enable the ServiceMonitor:

```bash
helm install spki-fingerprint-exporter oci://ghcr.io/samuelb/charts/spki-fingerprint-exporter \
  --set serviceMonitor.enabled=true \
  --set-string 'serviceMonitor.targets[0]=example.com:443'
```

Targets are `host:port` or a URL (`https://example.org`). Without an explicit
port, it is derived from the URL scheme.

## Values

| Key | Description | Default |
|-----|-------------|---------|
| `replicaCount` | Number of exporter replicas | `1` |
| `image.repository` | Image repository | `basa/spki-fingerprint-exporter` |
| `image.tag` | Image tag | chart `appVersion` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Pull secrets for private registries | `[]` |
| `nameOverride` | Override the chart name | `""` |
| `fullnameOverride` | Override the full resource name | `""` |
| `serviceAccount.create` | Create a dedicated ServiceAccount | `true` |
| `serviceAccount.name` | ServiceAccount name | generated from the fullname |
| `serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `serviceAccount.automount` | Mount the API token into the pod (the exporter needs no API access) | `false` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `3000` |
| `service.annotations` | Service annotations | `{}` |
| `containerPort` | Port the exporter listens on; also sets `LISTEN_ADDRESS` | `3000` |
| `listenHost` | Optional interface/address to bind (the container port is appended) | `""` |
| `healthProbes.livenessPath` | Liveness probe path | `/-/healthy` |
| `healthProbes.readinessPath` | Readiness probe path | `/-/ready` |
| `livenessProbe` | Full liveness probe spec; replaces the default httpGet probe when set | `{}` |
| `readinessProbe` | Full readiness probe spec; replaces the default httpGet probe when set | `{}` |
| `env` | Additional environment variables (e.g. `DEFAULT_TIMEOUT`, `MAX_CONCURRENT_PROBES`) | `[]` |
| `extraVolumes` | Additional pod volumes, e.g. a Secret holding a web config file | `[]` |
| `extraVolumeMounts` | Additional volume mounts for the exporter container | `[]` |
| `podAnnotations` | Extra pod annotations | `{}` |
| `podLabels` | Extra pod labels | `{}` |
| `podSecurityContext` | Pod security context | non-root, `RuntimeDefault` seccomp |
| `securityContext` | Container security context | read-only root FS, all capabilities dropped |
| `serviceMonitor.enabled` | Create a ServiceMonitor for the Prometheus Operator | `false` |
| `serviceMonitor.selfMonitor` | Also scrape the exporter's own `/metrics` endpoint | `true` |
| `serviceMonitor.targets` | TLS targets to probe (required when enabled, unless `selfMonitor` covers you) | `[]` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.additionalLabels` | Extra labels on the ServiceMonitor (e.g. to match a Prometheus selector) | `{}` |
| `serviceMonitor.scheme` | Scheme Prometheus uses to reach the exporter (`http` or `https`) | `""` (`http`) |
| `serviceMonitor.tlsConfig` | TLS settings for scraping an exporter that serves HTTPS | `{}` |
| `serviceMonitor.basicAuth` | Basic auth credentials (Secret key references) for scraping | `{}` |
| `prometheusRule.enabled` | Create a PrometheusRule for the Prometheus Operator | `false` |
| `prometheusRule.additionalLabels` | Extra labels on the PrometheusRule (e.g. to match a Prometheus rule selector) | `{}` |
| `prometheusRule.selector` | Label matchers that scope the built-in rules to this exporter | job and namespace of the chart's ServiceMonitor |
| `prometheusRule.rules` | Custom alerting rules; replace the built-in ones when set | `[]` (built-in rules) |
| `ingress.enabled` | Create an Ingress | `false` |
| `ingress.pathType` | Ingress path type | `ImplementationSpecific` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts and paths | see `values.yaml` |
| `ingress.tls` | Ingress TLS configuration | `[]` |
| `resources` | Container resource requests/limits | `{}` |
| `podDisruptionBudget.enabled` | Create a PodDisruptionBudget (useful with `replicaCount` > 1) | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods (mutually exclusive with `maxUnavailable`; set to `""` to use that instead) | `1` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods | `""` |
| `networkPolicy.enabled` | Create a NetworkPolicy restricting ingress to the exporter port | `false` |
| `networkPolicy.ingressFrom` | Peers allowed to reach the exporter (empty allows all) | `[]` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `priorityClassName` | Pod priority class | `""` |
| `topologySpreadConstraints` | Topology spread constraints | `[]` |

Notes:

- `containerPort` sets both the container port and the `LISTEN_ADDRESS`
  environment variable; do not add `LISTEN_ADDRESS` to `env` separately
  (the chart fails rendering if you do).
- For exporter images predating the health endpoints, set
  `healthProbes.livenessPath` and `healthProbes.readinessPath` to `/`.

## Alerting rules

With `prometheusRule.enabled`, the chart creates these alerts:

| Alert | Fires when |
|-------|------------|
| `SpkiFingerprintChanged` | a target presented more than one distinct fingerprint within the last hour |
| `SpkiProbeFailed` | a probe has been failing for 5 minutes |
| `SpkiProbesRejected` | the exporter rejected probes because of `MAX_CONCURRENT_PROBES` |
| `SpkiExporterDown` | Prometheus has not been able to scrape the exporter for 5 minutes |
| `SpkiExporterAbsent` | Prometheus has had no scrape target for the exporter for 10 minutes |

`probe_success` and `up` are shared metric names, so the rules only look at
series of this exporter. By default they match the job and namespace that
the chart's ServiceMonitor produces (`job="<fullname>"`,
`namespace="<release namespace>"`). If you scrape the exporter through your
own scrape config instead, set `prometheusRule.selector` to match it, for
example `job="spki-fingerprint-exporter"`. Otherwise the rules match
nothing and `SpkiExporterAbsent` fires.

To use your own rules, set `prometheusRule.rules`. They replace the built-in
rules and are rendered as given.

## TLS and basic auth

The exporter can protect its own listener with TLS and/or basic auth through
an [exporter-toolkit web config](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).
Store the file in a Secret, mount it, and point `WEB_CONFIG_FILE` at it:

```yaml
env:
  - name: WEB_CONFIG_FILE
    value: /etc/spki-exporter/web.yml
extraVolumes:
  - name: web-config
    secret:
      secretName: spki-exporter-web-config # key: web.yml
extraVolumeMounts:
  - name: web-config
    mountPath: /etc/spki-exporter
    readOnly: true

# Basic auth also applies to the health endpoints, and the kubelet sends no
# credentials: check that the port accepts connections instead.
livenessProbe:
  tcpSocket:
    port: http
readinessProbe:
  tcpSocket:
    port: http

# Tell Prometheus how to reach the protected listener.
serviceMonitor:
  enabled: true
  targets:
    - example.com:443
  scheme: https # only when the web config enables TLS
  tlsConfig:
    insecureSkipVerify: true # or ca/serverName for a verifiable certificate
  basicAuth:
    username:
      name: spki-exporter-scrape-credentials
      key: username
    password:
      name: spki-exporter-scrape-credentials
      key: password
```

With TLS but no basic auth, you can keep the HTTP health checks by setting
`scheme: HTTPS` in custom `livenessProbe`/`readinessProbe` specs.

## Metrics

Each ServiceMonitor target is scraped via `/probe?target=...` and yields:

```
spki_fingerprint{fingerprint="base64encodedsha256sumofspki=",target="example.com:443"} 1
probe_success 1
probe_duration_seconds 0.042
```

`probe_success` is `0` when the probe failed, so alerts can distinguish a
changed fingerprint from an unreachable target:

```
probe_success{instance="example.com:443"} == 1
unless on(instance)
spki_fingerprint{fingerprint="base64encodedsha256sumofspki="}
```

With `serviceMonitor.selfMonitor` enabled (the default), the exporter's own
`/metrics` endpoint is scraped as well, providing operational metrics such as
`spki_fingerprint_exporter_probes_total` and
`spki_fingerprint_exporter_rejected_probes_total`.

See the [project README](https://github.com/samuelb/spki-fingerprint-exporter)
for how to compute the expected fingerprint with `openssl` and configuration
details.

## Security considerations

`/probe` opens a TLS connection to any `host:port` a caller supplies, as is
common for blackbox-style exporters. Do not expose the exporter outside the
cluster; restrict access to your Prometheus servers with `networkPolicy`
and/or [basic auth](#tls-and-basic-auth).
