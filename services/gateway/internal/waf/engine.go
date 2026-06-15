package waf

import (
	"context"
	"net/http"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
)

type PolicyContext struct {
	RequestID string
	AppID     string
	Host      string
	ClientIP  string
	Mode      decision.Mode
}

type Engine interface {
	InspectRequest(ctx context.Context, req *http.Request, bodyPreview []byte, app PolicyContext) (*decision.Decision, error)
}

type AllowEngine struct{}

func (AllowEngine) InspectRequest(context.Context, *http.Request, []byte, PolicyContext) (*decision.Decision, error) {
	allow := decision.Allow()
	return &allow, nil
}
