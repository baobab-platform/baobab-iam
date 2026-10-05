package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationRefusesUnknownAndTrailingInput(t *testing.T) {
	for _, input := range []string{`{"Unknown":true}`, `{} {}`, `{} garbage`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := load(path); err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
}
