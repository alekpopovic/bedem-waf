package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Timestamp     time.Time `json:"timestamp"`
	RequestID     string    `json:"request_id"`
	AppID         string    `json:"app_id,omitempty"`
	Host          string    `json:"host"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Action        string    `json:"action"`
	Mode          string    `json:"mode,omitempty"`
	Status        int       `json:"status"`
	Reason        string    `json:"reason,omitempty"`
	MatchedRuleID string    `json:"matched_rule_id,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	LatencyMS     int64     `json:"latency_ms"`
	BodyPreview   string    `json:"body_preview,omitempty"`
}

type Logger interface {
	Log(Event)
}

type JSONLogger struct {
	mu  sync.Mutex
	out io.Writer
}

func NewJSONLogger(out io.Writer) *JSONLogger {
	return &JSONLogger{out: out}
}

func (l *JSONLogger) Log(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.out).Encode(event)
}
