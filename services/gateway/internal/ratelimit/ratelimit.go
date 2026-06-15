package ratelimit

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
)

type Limiter interface {
	Check(ctx context.Context, appID string, clientIP string, rule policy.RateLimitRule) decision.Decision
}

type NoopLimiter struct{}

func (NoopLimiter) Check(context.Context, string, string, policy.RateLimitRule) decision.Decision {
	return decision.Allow()
}

func FromConfig(cfg config.RedisConfig, logger *slog.Logger) (Limiter, error) {
	if !cfg.Enabled {
		return NoopLimiter{}, nil
	}
	return &RedisLimiter{Addr: cfg.Addr, Timeout: 500 * time.Millisecond, Logger: logger}, nil
}

type RedisLimiter struct {
	Addr    string
	Timeout time.Duration
	Logger  *slog.Logger
}

func (r *RedisLimiter) Check(ctx context.Context, appID string, clientIP string, rule policy.RateLimitRule) decision.Decision {
	if rule.Limit <= 0 || rule.WindowSeconds <= 0 {
		return decision.Allow()
	}
	keyValue := clientIP
	if rule.Key != "" && rule.Key != "ip" {
		keyValue = clientIP
	}
	redisKey := fmt.Sprintf("bedemwaf:ratelimit:%s:%s:%s", appID, rule.Name, keyValue)

	count, err := r.incr(ctx, redisKey, rule.WindowSeconds)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("rate_limit_redis_unavailable", "error", err, "rule", rule.Name)
		}
		return decision.Allow()
	}
	if count <= int64(rule.Limit) {
		return decision.Allow()
	}
	if rule.Action == decision.ActionBlock || rule.Action == decision.ActionRateLimit {
		return decision.RateLimit("rate_limit", "rate_limit:"+rule.Name)
	}
	return decision.Decision{Action: decision.ActionCount, Reason: "rate_limit", MatchedRuleID: "rate_limit:" + rule.Name}
}

func (r *RedisLimiter) incr(ctx context.Context, key string, windowSeconds int) (int64, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = time.Second
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn, "*2\r\n$4\r\nINCR\r\n$%d\r\n%s\r\n", len(key), key); err != nil {
		return 0, err
	}
	count, err := readInteger(reader)
	if err != nil {
		return 0, err
	}
	if count == 1 {
		if _, err := fmt.Fprintf(conn, "*3\r\n$6\r\nEXPIRE\r\n$%d\r\n%s\r\n$%d\r\n%d\r\n", len(key), key, len(strconv.Itoa(windowSeconds)), windowSeconds); err != nil {
			return 0, err
		}
		if _, err := readInteger(reader); err != nil {
			return 0, err
		}
	}
	return count, nil
}

func readInteger(reader *bufio.Reader) (int64, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "-") {
		return 0, fmt.Errorf("redis error: %s", strings.TrimPrefix(line, "-"))
	}
	if !strings.HasPrefix(line, ":") {
		return 0, fmt.Errorf("unexpected redis response: %q", line)
	}
	return strconv.ParseInt(strings.TrimPrefix(line, ":"), 10, 64)
}
