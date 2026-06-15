package ratelimit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
)

const fixedWindowLua = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[2])
end
local limit = tonumber(ARGV[1])
local remaining = limit - current
if remaining < 0 then
  remaining = 0
end
return {current, remaining}
`

type Limiter interface {
	Check(ctx context.Context, app *policy.App, req Request, rule policy.RateLimitRule) decision.Decision
}

type Request struct {
	ClientIP string
	Method   string
	Host     string
	Path     string
	Headers  http.Header
	Query    url.Values
}

type Store interface {
	IncrementFixedWindow(ctx context.Context, key string, limit int, windowSeconds int) (count int64, remaining int, err error)
}

type NoopLimiter struct{}

func (NoopLimiter) Check(context.Context, *policy.App, Request, policy.RateLimitRule) decision.Decision {
	return decision.Allow()
}

func FromConfig(cfg config.RedisConfig, logger *slog.Logger) (Limiter, error) {
	if !cfg.Enabled {
		return NoopLimiter{}, nil
	}
	failClosed := cfg.FailMode == "closed"
	return NewFixedWindowLimiter(&RedisStore{Addr: cfg.Addr, Timeout: 500 * time.Millisecond}, failClosed, logger), nil
}

type FixedWindowLimiter struct {
	store      Store
	failClosed bool
	logger     *slog.Logger
	now        func() time.Time
}

func NewFixedWindowLimiter(store Store, failClosed bool, logger *slog.Logger) *FixedWindowLimiter {
	return &FixedWindowLimiter{store: store, failClosed: failClosed, logger: logger, now: time.Now}
}

func (l *FixedWindowLimiter) Check(ctx context.Context, app *policy.App, req Request, rule policy.RateLimitRule) decision.Decision {
	if !rule.Enabled {
		return decision.Allow()
	}
	if rule.MatchExpression != nil {
		if !rule.MatchExpression.Match(policy.RequestContext{
			Method:   req.Method,
			Path:     req.Path,
			Host:     req.Host,
			Headers:  req.Headers,
			Query:    req.Query,
			ClientIP: parseAddr(req.ClientIP),
		}, app.IPSets) {
			return decision.Allow()
		}
	}
	keyPart := keyPartForRule(req, rule)
	keyHash := HashKeyPart(keyPart)
	now := l.now().UTC()
	window := now.Unix() / int64(rule.WindowSeconds)
	resetAt := time.Unix((window+1)*int64(rule.WindowSeconds), 0).UTC()
	redisKey := fmt.Sprintf("bedemwaf:rl:%s:%s:%s:%s:%d", app.TenantID, app.ID, rule.ID, keyHash, window)

	count, remaining, err := l.store.IncrementFixedWindow(ctx, redisKey, rule.Limit, rule.WindowSeconds)
	if err != nil {
		if l.logger != nil {
			l.logger.Warn("rate_limit_store_unavailable", "error", err, "rule_id", rule.ID, "fail_closed", l.failClosed)
		}
		if !l.failClosed {
			return decision.Allow()
		}
		return rateLimitDecision(rule, 0, resetAt)
	}
	if count <= int64(rule.Limit) {
		return decision.Decision{
			Action:          decision.ActionAllow,
			MatchedRuleName: rule.Name,
			RuleGroup:       "rate_limit",
			Tags:            []string{"rate_limit"},
			RateLimit: &decision.RateLimitInfo{
				Limit:     rule.Limit,
				Remaining: remaining,
				ResetAt:   resetAt,
				RuleID:    rule.ID,
				Action:    rule.Action,
			},
		}
	}
	return rateLimitDecision(rule, remaining, resetAt)
}

func rateLimitDecision(rule policy.RateLimitRule, remaining int, resetAt time.Time) decision.Decision {
	action := decision.ActionCount
	if rule.Action == decision.ActionBlock {
		action = decision.ActionRateLimit
	}
	return decision.Decision{
		Action:          action,
		Reason:          "rate_limit",
		MatchedRuleID:   "rate_limit:" + rule.ID,
		MatchedRuleName: rule.Name,
		RuleGroup:       "rate_limit",
		Tags:            []string{"rate_limit"},
		StatusCode:      rule.StatusCode,
		RateLimit: &decision.RateLimitInfo{
			Limit:     rule.Limit,
			Remaining: remaining,
			ResetAt:   resetAt,
			RuleID:    rule.ID,
			Action:    rule.Action,
		},
	}
}

func keyPartForRule(req Request, rule policy.RateLimitRule) string {
	switch rule.KeyType {
	case "host":
		return strings.ToLower(req.Host)
	case "path":
		return req.Path
	case "header":
		return req.Headers.Get(rule.KeyHeader)
	case "api_key_placeholder":
		return req.Headers.Get("X-API-Key")
	default:
		return req.ClientIP
	}
}

func HashKeyPart(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type RedisStore struct {
	Addr    string
	Timeout time.Duration
}

func (r *RedisStore) IncrementFixedWindow(ctx context.Context, key string, limit int, windowSeconds int) (int64, int, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = time.Second
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	args := []string{"EVAL", fixedWindowLua, "1", key, strconv.Itoa(limit), strconv.Itoa(windowSeconds)}
	if err := writeRESPArray(conn, args); err != nil {
		return 0, 0, err
	}
	values, err := readIntegerArray(reader)
	if err != nil {
		return 0, 0, err
	}
	if len(values) != 2 {
		return 0, 0, fmt.Errorf("unexpected redis lua response length %d", len(values))
	}
	return values[0], int(values[1]), nil
}

func writeRESPArray(conn net.Conn, values []string) error {
	if _, err := fmt.Fprintf(conn, "*%d\r\n", len(values)); err != nil {
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(value), value); err != nil {
			return err
		}
	}
	return nil
}

func readIntegerArray(reader *bufio.Reader) ([]int64, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "-") {
		return nil, fmt.Errorf("redis error: %s", strings.TrimPrefix(line, "-"))
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected redis array response: %q", line)
	}
	count, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil {
		return nil, err
	}
	values := make([]int64, 0, count)
	for i := 0; i < count; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ":") {
			return nil, fmt.Errorf("unexpected redis integer response: %q", line)
		}
		value, err := strconv.ParseInt(strings.TrimPrefix(line, ":"), 10, 64)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

type MemoryStore struct {
	mu     sync.Mutex
	counts map[string]int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{counts: map[string]int64{}}
}

func (m *MemoryStore) IncrementFixedWindow(_ context.Context, key string, limit int, _ int) (int64, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[key]++
	remaining := limit - int(m.counts[key])
	if remaining < 0 {
		remaining = 0
	}
	return m.counts[key], remaining, nil
}

type FailingStore struct {
	Err error
}

func (f FailingStore) IncrementFixedWindow(context.Context, string, int, int) (int64, int, error) {
	if f.Err != nil {
		return 0, 0, f.Err
	}
	return 0, 0, fmt.Errorf("rate limit store failure")
}

func parseAddr(value string) netip.Addr {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.IPv4Unspecified()
	}
	return addr
}
