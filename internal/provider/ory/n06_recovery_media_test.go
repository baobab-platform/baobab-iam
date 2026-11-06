package ory_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Kratos' original JSON media-type parameters must never erase a valid
// recovery flow state. A non-JSON/ambiguous response still fails closed.
func TestN06RecoveryOriginalProviderMediaAndState(t *testing.T) {
	for _, tc := range []struct {
		name string
		media string
		body string
		want string
	}{
		{"kratos-json-charset", "application/json; charset=utf-8", `{"state":"sent_email"}`, "sent_email"},
		{"kratos-plain-json", "application/json", `{"state":"passed_challenge"}`, "passed_challenge"},
		{"unreviewed-media", "text/html", `{"state":"passed_challenge"}`, ""},
		{"invalid-state", "application/json", `{"state":"unreviewed"}`, ""},
		{"invalid-json", "application/json", `{"state":`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(tc.body))}
			res.Header.Set("Content-Type", tc.media)
			got := n06ReadRecoveryDecision(res)
			if got.HTTP != http.StatusOK || got.State != tc.want {
				t.Fatal("original provider state misclassified")
			}
		})
	}
}
