package models

import (
	"encoding/json"
	"time"
)

type Tenant struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Status    string          `json:"status"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type CreateTenantRequest struct {
	Name     string          `json:"name"`
	Slug     string          `json:"slug"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

type App struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Hostnames []string        `json:"hostnames"`
	Status    string          `json:"status"`
	Origins   []Origin        `json:"origins,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Origin struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	URL    string `json:"url,omitempty"`
}

type CreateAppRequest struct {
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Hostnames []string        `json:"hostnames"`
	OriginURL string          `json:"origin_url"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type UpdateAppRequest struct {
	Name      *string         `json:"name,omitempty"`
	Hostnames []string        `json:"hostnames,omitempty"`
	OriginURL *string         `json:"origin_url,omitempty"`
	Status    *string         `json:"status,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type Policy struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	AppID           string          `json:"app_id"`
	Name            string          `json:"name"`
	Mode            string          `json:"mode"`
	Enabled         bool            `json:"enabled"`
	ActiveVersionID string          `json:"active_version_id,omitempty"`
	Snapshot        json.RawMessage `json:"snapshot,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name     string          `json:"name"`
	Mode     string          `json:"mode"`
	Snapshot json.RawMessage `json:"snapshot"`
}

type UpdatePolicyRequest struct {
	Name              *string         `json:"name,omitempty"`
	Mode              *string         `json:"mode,omitempty"`
	Enabled           *bool           `json:"enabled,omitempty"`
	Snapshot          json.RawMessage `json:"snapshot,omitempty"`
	ExpectedUpdatedAt time.Time       `json:"expected_updated_at"`
}

type PublishPolicyResponse struct {
	PolicyID        string    `json:"policy_id"`
	PolicyVersionID string    `json:"policy_version_id"`
	Version         int       `json:"version"`
	PublishedAt     time.Time `json:"published_at"`
}

type GatewayPolicy struct {
	TenantID        string          `json:"tenant_id"`
	AppID           string          `json:"app_id"`
	PolicyID        string          `json:"policy_id"`
	PolicyVersionID string          `json:"policy_version_id"`
	Mode            string          `json:"mode"`
	Origin          Origin          `json:"origin"`
	IPSets          json.RawMessage `json:"ip_sets"`
	CustomRules     json.RawMessage `json:"custom_rules"`
	RateLimits      json.RawMessage `json:"rate_limits"`
	WAF             json.RawMessage `json:"waf"`
	PublishedAt     time.Time       `json:"published_at"`
}

type ManagedRuleSet struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Provider    string          `json:"provider"`
	Source      string          `json:"source"`
	Description string          `json:"description,omitempty"`
	LocalPath   string          `json:"local_path,omitempty"`
	Enabled     bool            `json:"enabled"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type ManagedRuleVersion struct {
	ID               string          `json:"id"`
	ManagedRuleSetID string          `json:"managed_rule_set_id"`
	Version          string          `json:"version"`
	SourceURI        string          `json:"source_uri,omitempty"`
	LocalPath        string          `json:"local_path,omitempty"`
	ChecksumSHA256   string          `json:"checksum_sha256"`
	RulesetSnapshot  json.RawMessage `json:"ruleset_snapshot,omitempty"`
	ReleasedAt       *time.Time      `json:"released_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

type ActivateManagedRuleVersionResponse struct {
	ManagedRuleSetID     string `json:"managed_rule_set_id"`
	ManagedRuleVersionID string `json:"managed_rule_version_id"`
	Status               string `json:"status"`
	Message              string `json:"message"`
}

type EventRef struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	AppID      string          `json:"app_id,omitempty"`
	PolicyID   string          `json:"policy_id,omitempty"`
	EventID    string          `json:"event_id"`
	RequestID  string          `json:"request_id"`
	SourceIP   string          `json:"source_ip,omitempty"`
	Host       string          `json:"host,omitempty"`
	Path       string          `json:"path,omitempty"`
	Action     string          `json:"action"`
	OccurredAt time.Time       `json:"occurred_at"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}
