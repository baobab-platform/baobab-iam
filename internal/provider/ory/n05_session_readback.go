package ory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// ActiveSessionCount reads current Kratos Admin's identity session list,
// independently of DELETE /admin/identities/{id}/sessions. It is a narrow
// N05 identity-bound lifecycle observation, never a user-facing endpoint.
// A nil/malformed/redirected or untrusted issuer cannot become zero sessions.
func (a *Adapter) ActiveSessionCount(ctx context.Context, subject provider.ExternalSubject) (int, error) {
	if a == nil || ctx == nil {
		return 0, errors.New("ory: provider and context required")
	}
	if err := a.requireIssuer(subject); err != nil {
		return 0, err
	}
	endpoint := a.kratos.baseURL + "/admin/identities/" +
		url.PathEscape(subject.Subject) + "/sessions?active=true&page_size=2"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil { return 0, errors.New("ory: Kratos session readback unavailable") }
	request.Header.Set("Accept", "application/json")
	client := *a.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil { return 0, errors.New("ory: Kratos session readback unavailable") }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "application/json" {
		return 0, errors.New("ory: Kratos session readback not authoritative")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return 0, errors.New("ory: Kratos session readback size refused")
	}
	var entries []struct {
		ID string `json:"id"`
		Active *bool `json:"active"`
		IdentityID string `json:"identity_id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&entries); err != nil || entries == nil {
		return 0, errors.New("ory: Kratos session list malformed")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return 0, errors.New("ory: trailing Kratos session data")
	}
	for _, entry := range entries {
		if entry.ID == "" || entry.Active == nil || !*entry.Active ||
			entry.IdentityID != subject.Subject {
			return 0, errors.New("ory: Kratos session binding or active filter invalid")
		}
	}
	// With active=true and page_size=2, a zero-count list is authoritative
	// for an empty page; any nonzero result vetoes success, regardless of the
	// rest of the pagination or whether the caller intended to count sessions.
	return len(entries), nil
}
