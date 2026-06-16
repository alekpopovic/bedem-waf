package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registry = prometheus.NewRegistry()

var (
	jobsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_worker_jobs_total",
		Help: "Total worker jobs attempted.",
	}, []string{"job"})
	jobErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bedem_worker_job_errors_total",
		Help: "Total worker job errors.",
	}, []string{"job"})
)

func init() {
	registry.MustRegister(jobsTotal, jobErrorsTotal)
}

func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func IncJob(job string) {
	jobsTotal.WithLabelValues(label(job)).Inc()
}

func IncJobError(job string) {
	jobErrorsTotal.WithLabelValues(label(job)).Inc()
}

func label(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
