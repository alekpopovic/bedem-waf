package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registry = prometheus.NewRegistry()

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_control_api_requests_total",
		Help: "Total HTTP requests handled by the BedemWAF Control API.",
	}, []string{"method", "status"})
	requestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "bedem_control_api_request_duration_seconds",
		Help:    "Control API request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	})
	errorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_control_api_errors_total",
		Help: "Total HTTP errors returned by the BedemWAF Control API.",
	}, []string{"status"})
)

func init() {
	registry.MustRegister(requestsTotal, requestDuration, errorsTotal)
}

func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func ObserveRequest(method string, status int, duration time.Duration) {
	statusValue := strconv.Itoa(status)
	requestsTotal.WithLabelValues(method, statusValue).Inc()
	requestDuration.Observe(duration.Seconds())
	if status >= http.StatusBadRequest {
		errorsTotal.WithLabelValues(statusValue).Inc()
	}
}
