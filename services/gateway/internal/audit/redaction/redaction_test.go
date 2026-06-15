package redaction

import (
	"net/http"
	"strings"
	"testing"
)

func TestQueryRedaction(t *testing.T) {
	got := Query("username=demo&password=hunter2&access_token=abc123&page=1&code=oauth")

	for _, forbidden := range []string{"hunter2", "abc123", "oauth"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted query %q still contains sensitive value %q", got, forbidden)
		}
	}
	for _, want := range []string{"username=demo", "page=1", "password=%5BREDACTED%5D", "access_token=%5BREDACTED%5D", "code=%5BREDACTED%5D"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redacted query %q missing %q", got, want)
		}
	}
}

func TestSensitiveHeaderRedaction(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer secret"},
		"Cookie":        []string{"sid=secret"},
		"User-Agent":    []string{"BedemTest/1.0"},
	}

	got := Headers(headers)

	if got.Get("Authorization") != "[REDACTED]" {
		t.Fatalf("Authorization = %q, want redacted", got.Get("Authorization"))
	}
	if got.Get("Cookie") != "[REDACTED]" {
		t.Fatalf("Cookie = %q, want redacted", got.Get("Cookie"))
	}
	if got.Get("User-Agent") != "BedemTest/1.0" {
		t.Fatalf("User-Agent = %q, want preserved", got.Get("User-Agent"))
	}
}
