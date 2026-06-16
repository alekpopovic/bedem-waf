package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/metrics"
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
	Enforced        bool       `json:"enforced"`
	WouldBlock      bool       `json:"would_block"`
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

type ClickHouseConfig struct {
	URL      string
	Database string
	Username string
	Password string
}

type ClickHouseSink struct {
	endpoint   string
	database   string
	username   string
	password   string
	httpClient *http.Client
}

func NewClickHouseSink(cfg ClickHouseConfig, client *http.Client) (*ClickHouseSink, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid clickhouse url")
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	if cfg.Database == "" {
		cfg.Database = "bedemwaf"
	}
	return &ClickHouseSink{
		endpoint:   strings.TrimRight(parsed.String(), "/"),
		database:   cfg.Database,
		username:   cfg.Username,
		password:   cfg.Password,
		httpClient: client,
	}, nil
}

func (s *ClickHouseSink) Write(ctx context.Context, event Event) error {
	row := clickHouseEvent{
		Timestamp:       event.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
		RequestID:       event.RequestID,
		TenantID:        event.TenantID,
		AppID:           event.AppID,
		PolicyID:        event.PolicyID,
		PolicyVersionID: event.PolicyVersion,
		Host:            event.Host,
		ClientIP:        event.ClientIP,
		Method:          event.Method,
		Path:            event.Path,
		Action:          event.Action,
		Mode:            event.Mode,
		Enforced:        event.Enforced,
		WouldBlock:      event.WouldBlock,
		Status:          clampUInt16(event.Status),
		Reason:          event.Reason,
		MatchedRuleID:   event.MatchedRuleID,
		MatchedRuleName: event.MatchedRuleName,
		RuleGroup:       event.RuleGroup,
		Tags:            event.Tags,
		AnomalyScore:    int32(event.AnomalyScore),
		UserAgent:       event.UserAgent,
		LatencyMS:       clampUInt32(event.LatencyMS),
		OriginStatus:    clampUInt16(event.OriginStatus),
		OriginLatencyMS: clampUInt32(event.OriginLatencyMS),
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(row); err != nil {
		return err
	}
	query := `INSERT INTO waf_events FORMAT JSONEachRow`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/?database="+url.QueryEscape(s.database)+"&query="+url.QueryEscape(query), &body)
	if err != nil {
		return err
	}
	if s.username != "" || s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse insert failed: status=%d body=%q", resp.StatusCode, string(data))
	}
	return nil
}

type clickHouseEvent struct {
	Timestamp       string   `json:"timestamp"`
	RequestID       string   `json:"request_id"`
	TenantID        string   `json:"tenant_id"`
	AppID           string   `json:"app_id"`
	PolicyID        string   `json:"policy_id"`
	PolicyVersionID string   `json:"policy_version_id"`
	Host            string   `json:"host"`
	ClientIP        string   `json:"client_ip"`
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	Action          string   `json:"action"`
	Mode            string   `json:"mode"`
	Enforced        bool     `json:"enforced"`
	WouldBlock      bool     `json:"would_block"`
	Status          uint16   `json:"status"`
	Reason          string   `json:"reason"`
	MatchedRuleID   string   `json:"matched_rule_id"`
	MatchedRuleName string   `json:"matched_rule_name"`
	RuleGroup       string   `json:"rule_group"`
	Tags            []string `json:"tags"`
	AnomalyScore    int32    `json:"anomaly_score"`
	UserAgent       string   `json:"user_agent"`
	LatencyMS       uint32   `json:"latency_ms"`
	OriginStatus    uint16   `json:"origin_status"`
	OriginLatencyMS uint32   `json:"origin_latency_ms"`
}

func clampUInt16(value int) uint16 {
	if value < 0 {
		return 0
	}
	if value > 65535 {
		return 65535
	}
	return uint16(value)
}

func clampUInt32(value int64) uint32 {
	if value < 0 {
		return 0
	}
	if value > 1<<32-1 {
		return 1<<32 - 1
	}
	return uint32(value)
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
		metrics.IncAuditEventDropped()
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
	sent := false
	for _, sink := range d.sinks {
		if err := sink.Write(ctx, event); err != nil {
			d.logger.Warn("audit_event_send_failed", "error", err, "request_id", event.RequestID)
			continue
		}
		sent = true
	}
	if sent {
		d.metrics.eventsSentTotal.Add(1)
	}
}
