module github.com/baobab-platform/baobab-iam

go 1.22

// Gate IAM-M1: provider-neutral adapter contracts (ADR-IAM-0020).
// No third-party deps required for the interface layer or HTTP adapters
// (stdlib net/http only). Add Ory SDK modules later under Gate IAM-M2/M3
// if the project chooses generated clients over hand-written admin calls.
