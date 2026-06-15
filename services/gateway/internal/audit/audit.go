package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Timestamp       time.Time  `json:"timestamp"`
	RequestID       string     `json:"request_id"`
	TenantID        string     `json:"tenant_id"`
	AppID           string     `json:"app_id"`
	PolicyID        string     `json:"policy_id"`
	PolicyVersion   string     `json:"policy_version"`
	Host            string     `json:"host"`
	ClientIP        string     `json:"client_ip"`
	Country         string     `json:"country"`
	Method          string     `json:"method"`
	Path            string     `json:"path"`
	QueryRedacted   string     `json:"query_redacted"`
	UserAgent       string     `json:"user_agent"`
	Action          string     `json:"action"`
	Mode            string     `json:"mode"`
	Status          int        `json:"status"`
	Reason          string     `json:"reason"`
	MatchedRuleID   string     `json:"matched_rule_id"`
	MatchedRuleName string     `json:"matched_rule_name"`
	RuleGroup       string     `json:"rule_group"`
	Tags            []string   `json:"tags,omitempty"`
	AnomalyScore    int        `json:"anomaly_score"`
	RateLimit       *RateLimit `json:"rate_limit,omitempty"`
	LatencyMS       int64      `json:"latency_ms"`
	OriginStatus    int        `json:"origin_status"`
	OriginLatencyMS int64      `json:"origin_latency_ms"`
	BodyPreview     string     `json:"body_preview,omitempty"`
}

type RateLimit struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
	RuleID    string    `json:"rule_id"`
	Action    string    `json:"action"`
}

type Logger interface {
	Log(Event)
}

type Sink interface {
	Write(context.Context, Event) error
}

type JSONLogger struct {
	sink *JSONStdoutSink
}

func NewJSONLogger(out io.Writer) *JSONLogger {
	return &JSONLogger{sink: NewJSONStdoutSink(out)}
}

func (l *JSONLogger) Log(event Event) {
	_ = l.sink.Write(context.Background(), event)
}

type JSONStdoutSink struct {
	mu  sync.Mutex
	out io.Writer
}

func NewJSONStdoutSink(out io.Writer) *JSONStdoutSink {
	return &JSONStdoutSink{out: out}
}

func (s *JSONStdoutSink) Write(ctx context.Context, event Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewEncoder(s.out).Encode(event)
}

type ClickHouseSink struct{}

func NewClickHouseSink() *ClickHouseSink {
	return &ClickHouseSink{}
}

func (s *ClickHouseSink) Write(context.Context, Event) error {
	// TODO: Batch inserts into ClickHouse with retry/backoff and bounded memory.
	return nil
}

type Metrics struct {
	eventsSentTotal      atomic.Uint64
	eventsDroppedTotal   atomic.Uint64
	blockedRequestsTotal atomic.Uint64
	allowedRequestsTotal atomic.Uint64
}

func (m *Metrics) EventsSentTotal() uint64 {
	return m.eventsSentTotal.Load()
}

func (m *Metrics) EventsDroppedTotal() uint64 {
	return m.eventsDroppedTotal.Load()
}

func (m *Metrics) BlockedRequestsTotal() uint64 {
	return m.blockedRequestsTotal.Load()
}

func (m *Metrics) AllowedRequestsTotal() uint64 {
	return m.allowedRequestsTotal.Load()
}

type Dispatcher struct {
	queue   chan Event
	sinks   []Sink
	logger  *slog.Logger
	metrics *Metrics
	done    chan struct{}

	closeOnce sync.Once
}

func NewDispatcher(queueSize int, logger *slog.Logger, sinks ...Sink) (*Dispatcher, error) {
	if queueSize <= 0 {
		return nil, errors.New("audit queue size must be positive")
	}
	if len(sinks) == 0 {
		return nil, errors.New("at least one audit sink is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	d := &Dispatcher{
		queue:   make(chan Event, queueSize),
		sinks:   sinks,
		logger:  logger,
		metrics: &Metrics{},
		done:    make(chan struct{}),
	}
	go d.run()
	return d, nil
}

func (d *Dispatcher) Log(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Action == "block" || event.Action == "rate_limit" {
		d.metrics.blockedRequestsTotal.Add(1)
	} else {
		d.metrics.allowedRequestsTotal.Add(1)
	}
	select {
	case d.queue <- event:
	default:
		d.metrics.eventsDroppedTotal.Add(1)
		d.logger.Warn("audit_event_dropped", "reason", "queue_full", "request_id", event.RequestID)
	}
}

func (d *Dispatcher) Shutdown(ctx context.Context) error {
	d.closeOnce.Do(func() {
		close(d.queue)
	})
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Dispatcher) Metrics() *Metrics {
	return d.metrics
}

func (d *Dispatcher) run() {
	defer close(d.done)
	for event := range d.queue {
		d.write(event)
	}
}

func (d *Dispatcher) write(event Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, sink := range d.sinks {
		if err := sink.Write(ctx, event); err != nil {
			d.logger.Warn("audit_event_send_failed", "error", err, "request_id", event.RequestID)
			continue
		}
	}
	d.metrics.eventsSentTotal.Add(1)
}
