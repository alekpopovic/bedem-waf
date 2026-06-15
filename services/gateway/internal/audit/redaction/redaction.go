package redaction

import (
	"net/http"
	"net/url"
	"strings"
)

var sensitiveQueryNames = map[string]struct{}{
	"password":      {},
	"pass":          {},
	"token":         {},
	"access_token":  {},
	"refresh_token": {},
	"secret":        {},
	"api_key":       {},
	"key":           {},
	"code":          {},
}

var sensitiveHeaderNames = map[string]struct{}{
	"authorization": {},
	"cookie":        {},
}

const redactedValue = "[REDACTED]"

func Query(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return redactedValue
	}
	for name := range values {
		if IsSensitiveQueryName(name) {
			values[name] = []string{redactedValue}
		}
	}
	return values.Encode()
}

func Headers(headers http.Header) http.Header {
	redacted := make(http.Header, len(headers))
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if IsSensitiveHeaderName(name) {
			redacted[canonical] = []string{redactedValue}
			continue
		}
		redacted[canonical] = append([]string(nil), values...)
	}
	return redacted
}

func IsSensitiveQueryName(name string) bool {
	_, ok := sensitiveQueryNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func IsSensitiveHeaderName(name string) bool {
	_, ok := sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}
