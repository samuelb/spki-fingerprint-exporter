// Command spki-fingerprint-exporter is a Prometheus exporter that
// reports the SHA-256 fingerprint of the Subject Public Key Info (SPKI)
// in certificates presented by TLS services.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
)

var (
	// Version is set during build
	Version = "dev"

	// Default configuration
	defaultListenAddress = ":3000"
	defaultTimeout       = 10 * time.Second
	defaultMaxConcurrent = 64
	defaultLogFormat     = "text"
	scrapeTimeoutOffset  = 500 * time.Millisecond

	// schemePorts maps URL schemes to their default ports. A static map is
	// used instead of net.LookupPort because the latter depends on
	// /etc/services, which does not exist in minimal container images.
	schemePorts = map[string]string{
		"https":       "443",
		"smtps":       "465",
		"submissions": "465",
		"nntps":       "563",
		"ldaps":       "636",
		"domain-s":    "853",
		"ftps":        "990",
		"imaps":       "993",
		"pop3s":       "995",
		"sips":        "5061",
	}
)

type Config struct {
	ListenAddress       string
	DefaultTimeout      time.Duration
	MaxConcurrentProbes int
	LogLevel            slog.Level
	LogFormat           string
	WebConfigFile       string
}

// probeResult is the outcome of probing a single target.
type probeResult struct {
	success     bool
	fingerprint string
	// target is the probed target in host:port form.
	target   string
	duration time.Duration
}

type probeMetrics struct {
	active   prometheus.Gauge
	total    *prometheus.CounterVec
	rejected prometheus.Counter
}

func newProbeMetrics(registerer prometheus.Registerer) *probeMetrics {
	metrics := &probeMetrics{
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "active_probes",
			Help:      "Number of TLS probes currently being handled.",
		}),
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "probes_total",
			Help:      "Total number of completed TLS probes.",
		}, []string{"result"}),
		rejected: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "rejected_probes_total",
			Help:      "Total number of probes rejected because the concurrency limit was reached.",
		}),
	}
	registerer.MustRegister(metrics.active, metrics.total, metrics.rejected)
	metrics.total.WithLabelValues("success")
	metrics.total.WithLabelValues("failure")
	return metrics
}

// registry returns a registry holding the metrics of this probe result.
// spki_fingerprint is only present when the probe succeeded.
func (res probeResult) registry() *prometheus.Registry {
	fingerprint := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spki_fingerprint",
		Help: "TLS certificate Subject Public Key Info (SPKI) SHA-256 fingerprint.",
	}, []string{"fingerprint", "target"})
	duration := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	success := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})

	duration.Set(res.duration.Seconds())
	if res.success {
		fingerprint.WithLabelValues(res.fingerprint, res.target).Set(1)
		success.Set(1)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(fingerprint, duration, success)
	return registry
}

// runProbe probes rawTarget and reports the outcome.
func runProbe(ctx context.Context, rawTarget string, timeout time.Duration) (res probeResult) {
	start := time.Now()
	defer func() {
		res.duration = time.Since(start)
	}()

	target, err := parseTarget(rawTarget)
	if err != nil {
		slog.Error("Failed to parse target", "target", rawTarget, "error", err)
		return res
	}

	fingerprint, err := getFingerprint(ctx, target, timeout)
	if err != nil {
		slog.Error("Failed to get SPKI fingerprint", "target", target, "error", err)
		return res
	}

	res.success = true
	res.fingerprint = fingerprint
	res.target = target
	return res
}

func getFingerprint(ctx context.Context, target string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		// Certificate chain validation is intentionally skipped: this
		// exporter fingerprints the presented SPKI, it does not
		// validate the certificate.
		Config: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
	}

	netConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return "", fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer func() { _ = netConn.Close() }()

	conn := netConn.(*tls.Conn)
	connstate := conn.ConnectionState()
	if len(connstate.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates found")
	}

	// Hash the SPKI exactly as the server sent it rather than a
	// re-encoding of the parsed key.
	hash := sha256.Sum256(connstate.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func parseTarget(target string) (parsedTarget string, err error) {
	if !strings.Contains(target, "://") {
		target = "//" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", errors.New("hostname is required")
	}

	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", errors.New("port number is empty")
		}
		if u.Scheme == "" {
			return "", errors.New("protocol scheme or port number is required")
		}
		p, ok := schemePorts[strings.ToLower(u.Scheme)]
		if !ok {
			return "", fmt.Errorf("unknown default port for scheme %s, specify the port explicitly", u.Scheme)
		}
		port = p
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid port number %q", port)
	}

	return net.JoinHostPort(host, port), nil
}

func probeHandler(config Config, metrics *probeMetrics) http.HandlerFunc {
	maxConcurrent := config.MaxConcurrentProbes
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	probeSlots := make(chan struct{}, maxConcurrent)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target parameter is required", http.StatusBadRequest)
			return
		}

		timeout, err := getScrapeTimeout(r, config.DefaultTimeout)
		if err != nil {
			slog.Error("Failed to get scrape timeout", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		select {
		case probeSlots <- struct{}{}:
			if metrics != nil {
				metrics.active.Inc()
			}
		default:
			if metrics != nil {
				metrics.rejected.Inc()
			}
			w.Header().Set("Retry-After", "1")
			http.Error(w, "maximum concurrent probes reached", http.StatusServiceUnavailable)
			return
		}

		result := func() probeResult {
			// Deferred so that a panicking probe does not leak its slot.
			defer func() {
				<-probeSlots
				if metrics != nil {
					metrics.active.Dec()
				}
			}()
			return runProbe(r.Context(), target, timeout)
		}()
		if metrics != nil {
			outcome := "failure"
			if result.success {
				outcome = "success"
			}
			metrics.total.WithLabelValues(outcome).Inc()
		}

		promhttp.HandlerFor(result.registry(), promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}
}

func getScrapeTimeout(r *http.Request, defaultTimeout time.Duration) (time.Duration, error) {
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		timeoutSeconds, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse timeout from Prometheus header: %w", err)
		}
		if math.IsNaN(timeoutSeconds) || math.IsInf(timeoutSeconds, 0) || timeoutSeconds <= 0 {
			return 0, fmt.Errorf("scrape timeout from Prometheus header must be a positive finite number, got %q", v)
		}
		// Leave some headroom to respond before Prometheus closes the
		// connection, like the blackbox exporter does. For timeouts
		// shorter than twice the offset, reserve half the timeout so
		// there is always room to report probe_success 0.
		timeoutSeconds = math.Max(timeoutSeconds-scrapeTimeoutOffset.Seconds(), timeoutSeconds/2)
		if timeoutSeconds >= float64(math.MaxInt64)/float64(time.Second) {
			return 0, fmt.Errorf("scrape timeout from Prometheus header is too large: %q", v)
		}
		timeout := time.Duration(timeoutSeconds * float64(time.Second))
		if timeout <= 0 {
			return 0, fmt.Errorf("scrape timeout from Prometheus header is too small: %q", v)
		}
		return timeout, nil
	}
	return defaultTimeout, nil
}

func getConfig() (Config, error) {
	config := Config{
		ListenAddress:       defaultListenAddress,
		DefaultTimeout:      defaultTimeout,
		MaxConcurrentProbes: defaultMaxConcurrent,
		LogLevel:            slog.LevelInfo,
		LogFormat:           defaultLogFormat,
	}

	if addr := os.Getenv("LISTEN_ADDRESS"); addr != "" {
		config.ListenAddress = addr
	}

	if timeout := os.Getenv("DEFAULT_TIMEOUT"); timeout != "" {
		parsedTimeout, err := parseDefaultTimeout(timeout)
		if err != nil {
			return Config{}, err
		}
		config.DefaultTimeout = parsedTimeout
	}

	if value := os.Getenv("MAX_CONCURRENT_PROBES"); value != "" {
		maxConcurrent, err := strconv.Atoi(value)
		if err != nil || maxConcurrent <= 0 {
			return Config{}, fmt.Errorf("MAX_CONCURRENT_PROBES must be a positive integer, got %q", value)
		}
		config.MaxConcurrentProbes = maxConcurrent
	}

	config.WebConfigFile = os.Getenv("WEB_CONFIG_FILE")

	if value := os.Getenv("LOG_LEVEL"); value != "" {
		if err := config.LogLevel.UnmarshalText([]byte(value)); err != nil {
			return Config{}, fmt.Errorf("LOG_LEVEL must be debug, info, warn, or error, got %q", value)
		}
	}

	if value := os.Getenv("LOG_FORMAT"); value != "" {
		format := strings.ToLower(value)
		if format != "text" && format != "json" {
			return Config{}, fmt.Errorf("LOG_FORMAT must be text or json, got %q", value)
		}
		config.LogFormat = format
	}

	return config, nil
}

func setupLogger(config Config) {
	opts := &slog.HandlerOptions{Level: config.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if config.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func parseDefaultTimeout(value string) (time.Duration, error) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		if seconds <= 0 || seconds > int64(math.MaxInt64)/int64(time.Second) {
			return 0, fmt.Errorf("DEFAULT_TIMEOUT must be positive and fit in a duration, got %q", value)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("DEFAULT_TIMEOUT integer seconds value is out of range: %q", value)
	}

	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("failed to parse DEFAULT_TIMEOUT %q: use seconds or a Go duration: %w", value, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("DEFAULT_TIMEOUT must be positive, got %q", value)
	}
	return timeout, nil
}

func newHandler(config Config, registerer prometheus.Registerer, gatherer prometheus.Gatherer) http.Handler {
	version.Version = Version
	registerer.MustRegister(versioncollector.NewCollector("spki_fingerprint_exporter"))

	mux := http.NewServeMux()
	metricsHandler := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(registerer, metricsHandler))
	mux.HandleFunc("/probe", probeHandler(config, newProbeMetrics(registerer)))
	mux.HandleFunc("/-/healthy", healthHandler)
	mux.HandleFunc("/-/ready", healthHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<html>
			<head><title>SPKI fingerprint exporter</title></head>
			<body>
			<h1>SPKI fingerprint exporter</h1>
			<p>Version: %s</p>
			<p><a href="/probe?target=example.com:443">Probe example.com:443 for TLS certificate SPKI fingerprint metrics</a></p>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`, html.EscapeString(Version))
	})
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK\n"))
}

func newServer(config Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              config.ListenAddress,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

func serve(ctx context.Context, server *http.Server, listener net.Listener, webConfigFile string) error {
	errCh := make(chan error, 1)
	go func() {
		// With an empty config file path this is a plain HTTP server;
		// otherwise the exporter-toolkit enables TLS and/or basic auth
		// as configured.
		flags := &web.FlagConfig{WebConfigFile: &webConfigFile}
		errCh <- web.Serve(listener, server, flags, slog.Default())
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("Shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func run(ctx context.Context, config Config) error {
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", config.ListenAddress, err)
	}
	handler := newHandler(config, prometheus.DefaultRegisterer, prometheus.DefaultGatherer)
	return serve(ctx, newServer(config, handler), listener, config.WebConfigFile)
}

func main() {
	config, err := getConfig()
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}
	setupLogger(config)

	slog.Info("Starting server", "version", Version, "address", config.ListenAddress)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
