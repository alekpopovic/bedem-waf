package events

import (
	"strings"
	"testing"
	"time"
)

func TestBuildSearchQueryValidation(t *testing.T) {
	query, params, err := BuildSearchQuery(SearchFilters{
		TenantID: "tenant-1",
		AppID:    "app-1",
		PolicyID: "policy-1",
		Action:   "block",
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("BuildSearchQuery() error = %v", err)
	}
	for _, want := range []string{"tenant_id = {tenant_id:String}", "app_id = {app_id:String}", "policy_id = {policy_id:String}", "action = {action:String}", "LIMIT {limit:UInt32}"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query missing %q:\n%s", want, query)
		}
	}
	if params["tenant_id"] != "tenant-1" || params["limit"] != "50" {
		t.Fatalf("params = %+v, want tenant and limit", params)
	}
}

func TestBuildSimulationSummary(t *testing.T) {
	got := BuildSimulationSummary([]Event{
		{RequestID: "req-1", ClientIP: "198.51.100.10", Path: "/admin", MatchedRuleID: "rule-admin", MatchedRuleName: "Admin block", WouldBlock: true},
		{RequestID: "req-2", ClientIP: "198.51.100.11", Path: "/admin", MatchedRuleID: "rule-admin", MatchedRuleName: "Admin block", WouldBlock: true},
		{RequestID: "req-3", ClientIP: "198.51.100.11", Path: "/login", MatchedRuleID: "rule-login", MatchedRuleName: "Login block", WouldBlock: true},
		{RequestID: "req-4", ClientIP: "198.51.100.12", Path: "/", MatchedRuleID: "rule-allow", WouldBlock: false},
	})

	if len(got) != 2 {
		t.Fatalf("summary len = %d, want 2", len(got))
	}
	if got[0].RuleID != "rule-admin" || got[0].WouldBlockCount != 2 || got[0].UniqueIPs != 2 || len(got[0].SampleRequestIDs) != 2 {
		t.Fatalf("first summary = %+v, want rule-admin aggregate", got[0])
	}
	if got[1].RuleID != "rule-login" || got[1].WouldBlockCount != 1 {
		t.Fatalf("second summary = %+v, want rule-login aggregate", got[1])
	}
}

func TestLimitEnforcement(t *testing.T) {
	if _, params, err := BuildSearchQuery(SearchFilters{}); err != nil || params["limit"] != "100" {
		t.Fatalf("default limit params=%+v err=%v, want 100", params, err)
	}
	if _, _, err := BuildSearchQuery(SearchFilters{Limit: 1001}); err == nil {
		t.Fatal("BuildSearchQuery() error = nil, want max limit error")
	}
	if _, _, err := BuildSearchQuery(SearchFilters{Limit: -1}); err == nil {
		t.Fatal("BuildSearchQuery() error = nil, want min limit error")
	}
}

func TestDateRangeValidation(t *testing.T) {
	from := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	to := from.Add(-time.Hour)
	if _, _, err := BuildSearchQuery(SearchFilters{From: from, To: to}); err == nil {
		t.Fatal("BuildSearchQuery() error = nil, want invalid range error")
	}

	query, params, err := BuildSearchQuery(SearchFilters{From: to, To: from})
	if err != nil {
		t.Fatalf("BuildSearchQuery() error = %v", err)
	}
	if !strings.Contains(query, "parseDateTime64BestEffort({from:String}, 3)") || params["from"] == "" || params["to"] == "" {
		t.Fatalf("query=%s params=%+v, want date filters", query, params)
	}
}
