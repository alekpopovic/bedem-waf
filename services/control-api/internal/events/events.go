package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

type SearchFilters struct {
	TenantID      string
	AppID         string
	PolicyID      string
	Host          string
	Action        string
	ClientIP      string
	MatchedRuleID string
	From          time.Time
	To            time.Time
	Limit         int
}

type Event struct {
	Timestamp       time.Time `json:"timestamp"`
	RequestID       string    `json:"request_id"`
	TenantID        string    `json:"tenant_id"`
	AppID           string    `json:"app_id"`
	PolicyID        string    `json:"policy_id"`
	PolicyVersionID string    `json:"policy_version_id"`
	Host            string    `json:"host"`
	ClientIP        string    `json:"client_ip"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	Action          string    `json:"action"`
	Mode            string    `json:"mode"`
	Enforced        bool      `json:"enforced"`
	WouldBlock      bool      `json:"would_block"`
	Status          uint16    `json:"status"`
	Reason          string    `json:"reason"`
	MatchedRuleID   string    `json:"matched_rule_id"`
	MatchedRuleName string    `json:"matched_rule_name"`
	RuleGroup       string    `json:"rule_group"`
	Tags            []string  `json:"tags"`
	AnomalyScore    int32     `json:"anomaly_score"`
	UserAgent       string    `json:"user_agent"`
	LatencyMS       uint32    `json:"latency_ms"`
	OriginStatus    uint16    `json:"origin_status"`
	OriginLatencyMS uint32    `json:"origin_latency_ms"`
}

type Store interface {
	Search(context.Context, SearchFilters) ([]Event, error)
	GetByRequestID(context.Context, string, string) (Event, error)
}

type SimulationRuleSummary struct {
	RuleID           string   `json:"rule_id"`
	RuleName         string   `json:"rule_name"`
	WouldBlockCount  int      `json:"would_block_count"`
	UniqueIPs        int      `json:"unique_ips"`
	TopPaths         []string `json:"top_paths"`
	SampleRequestIDs []string `json:"sample_request_ids"`
}

type HTTPStore struct {
	endpoint   string
	database   string
	username   string
	password   string
	httpClient *http.Client
}

type Config struct {
	URL      string
	Database string
	Username string
	Password string
}

func NewHTTPStore(cfg Config, client *http.Client) (*HTTPStore, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid clickhouse url")
	}
	if cfg.Database == "" {
		cfg.Database = "bedemwaf"
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &HTTPStore{
		endpoint:   strings.TrimRight(parsed.String(), "/"),
		database:   cfg.Database,
		username:   cfg.Username,
		password:   cfg.Password,
		httpClient: client,
	}, nil
}

func (s *HTTPStore) Search(ctx context.Context, filters SearchFilters) ([]Event, error) {
	query, params, err := BuildSearchQuery(filters)
	if err != nil {
		return nil, err
	}
	data, err := s.query(ctx, query, params)
	if err != nil {
		return nil, err
	}
	return decodeEvents(data)
}

func (s *HTTPStore) GetByRequestID(ctx context.Context, tenantID string, requestID string) (Event, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Event{}, errors.New("tenant_id is required")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return Event{}, errors.New("request_id is required")
	}
	query := selectFields() + `
FROM waf_events
WHERE tenant_id = {tenant_id:String}
  AND request_id = {request_id:String}
ORDER BY timestamp DESC
LIMIT 1
FORMAT JSONEachRow`
	data, err := s.query(ctx, query, map[string]string{"tenant_id": tenantID, "request_id": requestID})
	if err != nil {
		return Event{}, err
	}
	events, err := decodeEvents(data)
	if err != nil {
		return Event{}, err
	}
	if len(events) == 0 {
		return Event{}, ErrNotFound
	}
	return events[0], nil
}

var ErrNotFound = errors.New("event not found")

func BuildSearchQuery(filters SearchFilters) (string, map[string]string, error) {
	if filters.Limit == 0 {
		filters.Limit = DefaultLimit
	}
	if filters.Limit < 1 || filters.Limit > MaxLimit {
		return "", nil, fmt.Errorf("limit must be between 1 and %d", MaxLimit)
	}
	if !filters.From.IsZero() && !filters.To.IsZero() && filters.From.After(filters.To) {
		return "", nil, errors.New("from must be before to")
	}

	clauses := []string{"1 = 1"}
	params := map[string]string{"limit": strconv.Itoa(filters.Limit)}
	addStringFilter := func(field, name, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		clauses = append(clauses, field+" = {"+name+":String}")
		params[name] = value
	}
	addStringFilter("tenant_id", "tenant_id", filters.TenantID)
	addStringFilter("app_id", "app_id", filters.AppID)
	addStringFilter("policy_id", "policy_id", filters.PolicyID)
	addStringFilter("host", "host", filters.Host)
	addStringFilter("action", "action", filters.Action)
	addStringFilter("client_ip", "client_ip", filters.ClientIP)
	addStringFilter("matched_rule_id", "matched_rule_id", filters.MatchedRuleID)
	if !filters.From.IsZero() {
		clauses = append(clauses, "timestamp >= parseDateTime64BestEffort({from:String}, 3)")
		params["from"] = filters.From.UTC().Format(time.RFC3339Nano)
	}
	if !filters.To.IsZero() {
		clauses = append(clauses, "timestamp <= parseDateTime64BestEffort({to:String}, 3)")
		params["to"] = filters.To.UTC().Format(time.RFC3339Nano)
	}

	query := selectFields() + `
FROM waf_events
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY timestamp DESC
LIMIT {limit:UInt32}
FORMAT JSONEachRow`
	return query, params, nil
}

func BuildSimulationSummary(input []Event) []SimulationRuleSummary {
	type accumulator struct {
		ruleName string
		count    int
		ips      map[string]struct{}
		paths    map[string]int
		samples  []string
	}
	byRule := map[string]*accumulator{}
	for _, event := range input {
		if !event.WouldBlock {
			continue
		}
		ruleID := strings.TrimSpace(event.MatchedRuleID)
		if ruleID == "" {
			ruleID = "unknown"
		}
		got := byRule[ruleID]
		if got == nil {
			got = &accumulator{ruleName: event.MatchedRuleName, ips: map[string]struct{}{}, paths: map[string]int{}}
			byRule[ruleID] = got
		}
		got.count++
		if event.ClientIP != "" {
			got.ips[event.ClientIP] = struct{}{}
		}
		if event.Path != "" {
			got.paths[event.Path]++
		}
		if event.RequestID != "" && len(got.samples) < 5 {
			got.samples = append(got.samples, event.RequestID)
		}
	}
	out := make([]SimulationRuleSummary, 0, len(byRule))
	for ruleID, got := range byRule {
		out = append(out, SimulationRuleSummary{
			RuleID:           ruleID,
			RuleName:         got.ruleName,
			WouldBlockCount:  got.count,
			UniqueIPs:        len(got.ips),
			TopPaths:         topPaths(got.paths, 5),
			SampleRequestIDs: got.samples,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WouldBlockCount == out[j].WouldBlockCount {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].WouldBlockCount > out[j].WouldBlockCount
	})
	return out
}

func topPaths(counts map[string]int, limit int) []string {
	type item struct {
		path  string
		count int
	}
	items := make([]item, 0, len(counts))
	for path, count := range counts {
		items = append(items, item{path: path, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].path < items[j].path
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.path)
	}
	return out
}

func (s *HTTPStore) query(ctx context.Context, query string, params map[string]string) ([]byte, error) {
	values := url.Values{}
	values.Set("database", s.database)
	values.Set("query", query)
	for name, value := range params {
		values.Set("param_"+name, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if s.username != "" || s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse query failed: status=%d body=%q", resp.StatusCode, string(data))
	}
	return data, nil
}

func decodeEvents(data []byte) ([]Event, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var events []Event
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func selectFields() string {
	return `SELECT
formatDateTime(timestamp, '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS timestamp,
request_id,
tenant_id,
app_id,
policy_id,
policy_version_id,
host,
client_ip,
method,
path,
action,
mode,
enforced,
would_block,
status,
reason,
matched_rule_id,
matched_rule_name,
rule_group,
tags,
anomaly_score,
user_agent,
latency_ms,
origin_status,
origin_latency_ms
`
}
