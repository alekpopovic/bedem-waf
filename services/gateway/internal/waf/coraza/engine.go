package coraza

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"

	corazalib "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/waf"
)

type Engine struct {
	waf        corazalib.WAF
	ruleEngine string
}

func New(cfg config.WAFConfig) (*Engine, error) {
	directives := fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit %d
SecRequestBodyLimitAction ProcessPartial
`, cfg.RuleEngine, cfg.RequestBodyLimitBytes)

	wafConfig := corazalib.NewWAFConfig().WithDirectives(directives)
	if cfg.DirectivesFile != "" {
		wafConfig = wafConfig.WithDirectivesFromFile(cfg.DirectivesFile)
	}
	instance, err := corazalib.NewWAF(wafConfig)
	if err != nil {
		return nil, err
	}
	return &Engine{waf: instance, ruleEngine: cfg.RuleEngine}, nil
}

func (e *Engine) InspectRequest(ctx context.Context, req *http.Request, bodyPreview []byte, app waf.PolicyContext) (*decision.Decision, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	tx := e.waf.NewTransactionWithID(app.RequestID)
	defer tx.Close()
	defer tx.ProcessLogging()

	clientPort := 0
	if _, port, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		clientPort, _ = strconv.Atoi(port)
	}
	tx.ProcessConnection(app.ClientIP, clientPort, app.Host, 0)
	tx.SetServerName(app.Host)
	tx.ProcessURI(req.URL.RequestURI(), req.Method, req.Proto)
	addHeaders(tx, req)

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return interruptionDecision(interruption), nil
	}

	if len(bodyPreview) > 0 {
		if interruption, _, err := tx.WriteRequestBody(bodyPreview); err != nil {
			return nil, err
		} else if interruption != nil {
			return interruptionDecision(interruption), nil
		}
	}
	if interruption, err := tx.ProcessRequestBody(); err != nil {
		return nil, err
	} else if interruption != nil {
		return interruptionDecision(interruption), nil
	}

	matches := tx.MatchedRules()
	if len(matches) == 0 {
		allow := decision.Allow()
		return &allow, nil
	}

	first := matches[0]
	matchedRuleID := fmt.Sprintf("coraza:%d", first.Rule().ID())
	for _, match := range matches {
		if match.Disruptive() {
			matchedRuleID = fmt.Sprintf("coraza:%d", match.Rule().ID())
			if e.ruleEngine == "DetectionOnly" {
				count := decision.Count("waf_match", matchedRuleID)
				count.RuleGroup = "coraza"
				count.Tags = []string{"waf", "coraza"}
				return &count, nil
			}
			block := decision.Block("waf_match", matchedRuleID)
			block.RuleGroup = "coraza"
			block.Tags = []string{"waf", "coraza"}
			return &block, nil
		}
	}
	count := decision.Count("waf_match", matchedRuleID)
	count.RuleGroup = "coraza"
	count.Tags = []string{"waf", "coraza"}
	return &count, nil
}

func addHeaders(tx types.Transaction, req *http.Request) {
	tx.AddRequestHeader("Host", req.Host)
	for key, values := range req.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
}

func interruptionDecision(interruption *types.Interruption) *decision.Decision {
	ruleID := "coraza"
	if interruption.RuleID != 0 {
		ruleID = fmt.Sprintf("coraza:%d", interruption.RuleID)
	}
	block := decision.Block("waf_interruption", ruleID)
	block.RuleGroup = "coraza"
	block.Tags = []string{"waf", "coraza"}
	return &block
}
