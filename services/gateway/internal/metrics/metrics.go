package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registry = prometheus.NewRegistry()

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_requests_total",
		Help: "Total requests processed by the BedemWAF gateway.",
	}, []string{"app_id", "host", "action"})
	blockedRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_blocked_requests_total",
		Help: "Total requests blocked by the BedemWAF gateway.",
	}, []string{"app_id", "reason"})
	requestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "bedem_request_duration_seconds",
		Help:    "Gateway request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	})
	originDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "bedem_origin_duration_seconds",
		Help:    "Origin upstream request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	})
	policyCacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bedem_policy_cache_hits_total",
		Help: "Total remote policy cache hits.",
	})
	policyCacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bedem_policy_cache_misses_total",
		Help: "Total remote policy cache misses.",
	})
	policyFetchErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bedem_policy_fetch_errors_total",
		Help: "Total remote policy fetch errors.",
	})
	rateLimitedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bedem_rate_limited_total",
		Help: "Total requests that matched a rate limit rule.",
	})
	auditEventsDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bedem_audit_events_dropped_total",
		Help: "Total audit events dropped before delivery.",
	})
)

func init() {
	registry.MustRegister(
		requestsTotal,
		blockedRequestsTotal,
		requestDuration,
		originDuration,
		policyCacheHitsTotal,
		policyCacheMissesTotal,
		policyFetchErrorsTotal,
		rateLimitedTotal,
		auditEventsDroppedTotal,
	)
}

func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func ObserveRequest(appID string, host string, action string, reason string, status int, duration time.Duration) {
	requestsTotal.WithLabelValues(label(appID), label(host), label(action)).Inc()
	requestDuration.Observe(duration.Seconds())
	if status >= http.StatusBadRequest || action == "block" || action == "rate_limit" {
		blockedRequestsTotal.WithLabelValues(label(appID), label(reason)).Inc()
	}
}

func ObserveOrigin(duration time.Duration) {
	originDuration.Observe(duration.Seconds())
}

func IncPolicyCacheHit() {
	policyCacheHitsTotal.Inc()
}

func IncPolicyCacheMiss() {
	policyCacheMissesTotal.Inc()
}

func IncPolicyFetchError() {
	policyFetchErrorsTotal.Inc()
}

func IncRateLimited() {
	rateLimitedTotal.Inc()
}

func IncAuditEventDropped() {
	auditEventsDroppedTotal.Inc()
}

func label(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
