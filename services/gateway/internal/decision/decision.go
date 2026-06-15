package decision

import "time"

type Action string

const (
	ActionAllow     Action = "allow"
	ActionCount     Action = "count"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionRateLimit Action = "rate_limit"
)

type Mode string

const (
	ModeCount Mode = "count"
	ModeBlock Mode = "block"
)

type Decision struct {
	Action          Action
	Reason          string
	MatchedRuleID   string
	MatchedRuleName string
	RuleGroup       string
	Tags            []string
	AnomalyScore    int
	StatusCode      int
	RateLimit       *RateLimitInfo
}

type RateLimitInfo struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
	RuleID    string
	Action    Action
}

func Allow() Decision {
	return Decision{Action: ActionAllow}
}

func Block(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionBlock, Reason: reason, MatchedRuleID: matchedRuleID, StatusCode: 403}
}

func RateLimit(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionRateLimit, Reason: reason, MatchedRuleID: matchedRuleID}
}

func Count(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionCount, Reason: reason, MatchedRuleID: matchedRuleID}
}

func AllowRule(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionAllow, Reason: reason, MatchedRuleID: matchedRuleID}
}

func WithStatus(d Decision, statusCode int) Decision {
	d.StatusCode = statusCode
	return d
}

func (d Decision) WouldBlock() bool {
	return d.Action == ActionBlock || d.Action == ActionRateLimit || d.Action == ActionChallenge
}

func EnforcedAction(mode Mode, d Decision) Action {
	if mode == ModeCount && d.WouldBlock() {
		return ActionCount
	}
	return d.Action
}
