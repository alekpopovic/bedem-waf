package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestAsyncDispatcherDrainsOnShutdown(t *testing.T) {
	sink := &memorySink{}
	dispatcher, err := NewDispatcher(4, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), sink)
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	dispatcher.Log(Event{RequestID: "req-1", Action: "allow"})
	dispatcher.Log(Event{RequestID: "req-2", Action: "block"})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	if len(sink.events) != 2 {
		t.Fatalf("events written = %d, want 2", len(sink.events))
	}
	if dispatcher.Metrics().EventsSentTotal() != 2 {
		t.Fatalf("events_sent_total = %d, want 2", dispatcher.Metrics().EventsSentTotal())
	}
}

func TestAsyncDispatcherDropsWhenQueueFull(t *testing.T) {
	sink := &blockingSink{started: make(chan struct{}), release: make(chan struct{})}
	dispatcher, err := NewDispatcher(1, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), sink)
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	dispatcher.Log(Event{RequestID: "req-block-worker", Action: "allow"})
	<-sink.started
	dispatcher.Log(Event{RequestID: "req-fill-queue", Action: "allow"})
	dispatcher.Log(Event{RequestID: "req-drop", Action: "allow"})

	if got := dispatcher.Metrics().EventsDroppedTotal(); got != 1 {
		t.Fatalf("events_dropped_total = %d, want 1", got)
	}

	close(sink.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestEventJSONSchemaStabilitySnapshot(t *testing.T) {
	var out bytes.Buffer
	sink := NewJSONStdoutSink(&out)
	event := Event{
		Timestamp:       time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
		RequestID:       "req-test",
		TenantID:        "tenant-local",
		AppID:           "app-local",
		PolicyID:        "policy-local",
		PolicyVersion:   "1",
		Host:            "example.local",
		ClientIP:        "198.51.100.10",
		Country:         "ZZ",
		Method:          "GET",
		Path:            "/login",
		QueryRedacted:   "token=%5BREDACTED%5D",
		UserAgent:       "BedemTest/1.0",
		Action:          "block",
		Mode:            "block",
		Status:          403,
		Reason:          "custom_rule",
		MatchedRuleID:   "rule-login",
		MatchedRuleName: "Login protection",
		RuleGroup:       "custom",
		Tags:            []string{"custom"},
		AnomalyScore:    5,
		RateLimit: &RateLimit{
			Limit:     100,
			Remaining: 0,
			ResetAt:   time.Date(2026, 6, 16, 12, 1, 0, 0, time.UTC),
			RuleID:    "rl-login",
			Action:    "block",
		},
		LatencyMS:       12,
		OriginStatus:    0,
		OriginLatencyMS: 0,
	}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("audit json invalid: %v", err)
	}
	for _, field := range []string{
		"timestamp", "request_id", "tenant_id", "app_id", "policy_id", "policy_version",
		"host", "client_ip", "country", "method", "path", "query_redacted", "user_agent",
		"action", "mode", "status", "reason", "matched_rule_id", "matched_rule_name",
		"rule_group", "tags", "anomaly_score", "rate_limit", "latency_ms",
	} {
		if _, ok := got[field]; !ok {
			t.Fatalf("audit event missing field %q in %s", field, out.String())
		}
	}
}

type memorySink struct {
	events []Event
}

func (s *memorySink) Write(_ context.Context, event Event) error {
	s.events = append(s.events, event)
	return nil
}

type blockingSink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSink) Write(ctx context.Context, event Event) error {
	s.once.Do(func() {
		close(s.started)
	})
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
