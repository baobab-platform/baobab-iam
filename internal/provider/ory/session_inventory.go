package ory

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
)

// EmptyActiveSessionInventory verifies a response to the pinned Kratos
// active-session list request. Kratos sends pagination links even at total
// zero, so require its explicit count and an empty JSON array.
func EmptyActiveSessionInventory(response *http.Response) bool {
	if response == nil || response.StatusCode != http.StatusOK {
		return false
	}
	counts := response.Header.Values("X-Total-Count")
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if len(counts) != 1 || counts[0] != "0" || err != nil || media != "application/json" {
		return false
	}
	const maxInventory = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxInventory+1))
	if err != nil || len(raw) > maxInventory {
		return false
	}
	var sessions []json.RawMessage
	return json.Unmarshal(raw, &sessions) == nil && sessions != nil && len(sessions) == 0
}
