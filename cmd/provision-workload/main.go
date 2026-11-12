// Command provision-workload produces a read-only Hydra workload plan from the
// pinned Shared registry. The reviewed profiles are production identities.
// Mutation requires a separately governed issuer and lifecycle.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var m4ClientCredentials = []string{
	"baobab-trade-workload",
	"baobab-cms-workload",
	"baobab-erp-workload",
	"baobab-pulse-workload",
	"thamani-backend",
	"zuribeans-backend",
}

type workloadPlan struct {
	LogicalClientID string   `json:"logical_client_id"`
	Environment     string   `json:"environment"`
	RegistryCommit  string   `json:"registry_commit"`
	Scopes          []string `json:"scopes"`
	Audiences       []string `json:"audiences"`
}

func run(getenv func(string) string, output io.Writer) error {
	if getenv("ORY_ACTION") != "plan" {
		return errors.New("set ORY_ACTION=plan for offline validation; live mutations require an independently governed issuer lifecycle")
	}
	id := getenv("ORY_LOGICAL_CLIENT_ID")
	scopes := strings.Split(getenv("ORY_ALLOWED_SCOPES"), ",")
	plan, err := approvedProvision(id, scopes)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(plan)
}

func main() {
	if err := run(os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "provision-workload:", err)
		os.Exit(2)
	}
}
