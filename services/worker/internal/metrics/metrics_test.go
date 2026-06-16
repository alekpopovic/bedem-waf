package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExposesWorkerMetrics(t *testing.T) {
	IncJob("test_job")
	IncJobError("test_job")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "bedem_worker_jobs_total") || !strings.Contains(body, "bedem_worker_job_errors_total") {
		t.Fatalf("metrics body missing worker metrics: %s", body)
	}
}
