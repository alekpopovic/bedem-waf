package decision

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
	Action        Action
	Reason        string
	MatchedRuleID string
}

func Allow() Decision {
	return Decision{Action: ActionAllow}
}

func Block(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionBlock, Reason: reason, MatchedRuleID: matchedRuleID}
}

func RateLimit(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionRateLimit, Reason: reason, MatchedRuleID: matchedRuleID}
}

func Count(reason, matchedRuleID string) Decision {
	return Decision{Action: ActionCount, Reason: reason, MatchedRuleID: matchedRuleID}
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
