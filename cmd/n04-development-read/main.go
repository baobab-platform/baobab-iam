// Command n04-development-read is a strictly read-only operator probe of the
// real CP identity-runtime private endpoint. It is NOT a provider registrar,
// approval, engine consumer test or development-acceptance certificate.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/pkg/workloadresource"
)

type config struct {
	Schema         string `json:"schema"`
	Environment    string `json:"environment"`
	RunID          string `json:"run_id"`
	IAMSourceSHA   string `json:"iam_source_sha"`
	SharedSourceSHA string `json:"shared_source_sha"`
	CPSourceSHA    string `json:"cp_source_sha"`
	CPOrigin       string `json:"cp_origin"`
	CARootFile     string `json:"ca_root_file"`
	TokenFile      string `json:"token_file"`
	Target         workloadresource.CPBindingTarget `json:"target"`
}
var shaPattern = regexp.MustCompile("^[0-9a-f]{40}$")
var runPattern = regexp.MustCompile("^[0-9a-f]{32}$")

func privateFile(path string, max int64) ([]byte, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, errors.New("absolute private path required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() < 1 || info.Size() > max {
		return nil, errors.New("untrusted private file")
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("private file read failed")
	}
	// Do not permit an ordinary file to become a different underlying inode
	// while the reader is contacting a network service.
	again, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, again) {
		return nil, errors.New("private file identity changed")
	}
	return data, nil
}

func checkedConfig(path string) (config, error) {
	var out config
	content, err := privateFile(path, 16384)
	if err != nil {
		return out, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil {
		return config{}, errors.New("malformed exact N04 config")
	}
	var unexpected any
	if decoder.Decode(&unexpected) == nil {
		return config{}, errors.New("trailing config")
	}
	if out.Schema != "baobab.iam.n04.dev-read-config.v1" ||
		out.Environment != "development" ||
		!runPattern.MatchString(out.RunID) ||
		!shaPattern.MatchString(out.IAMSourceSHA) ||
		!shaPattern.MatchString(out.SharedSourceSHA) ||
		!shaPattern.MatchString(out.CPSourceSHA) {
		return config{}, errors.New("development/source pin mismatch")
	}
	return out, nil
}

func probe(ctx context.Context, c config) error {
	ca, err := privateFile(c.CARootFile, 128*1024)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("untrusted private CP CA")
	}
	getToken := func(context.Context) (string, error) {
		content, err := privateFile(c.TokenFile, 16384)
		if err != nil {
			return "", err
		}
		raw := string(content)
		if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t") {
			return "", errors.New("invalid private token")
		}
		return raw, nil
	}
	reader, err := workloadresource.NewCPRegisteredBinding(
		c.CPOrigin, roots, c.Target, getToken)
	if err != nil {
		return err
	}
	return reader.CheckCapability(ctx, workloadresource.WorkloadIssueCapability)
}

func main() {
	settings := flag.String("settings", "", "absolute private 0600 development source-pinned configuration")
	flag.Parse()
	if flag.NArg() != 0 || os.Getenv("BAOBAB_ENVIRONMENT") != "development" {
		fmt.Fprintln(os.Stderr, "N04_DEVELOPMENT_ONLY_HELD")
		os.Exit(2)
	}
	c, err := checkedConfig(*settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "N04_CONFIG_OR_PROVENANCE_HELD")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := probe(ctx,c); err != nil {
		// Do not print provider details, token contents, transport URLs or
		// potentially sensitive CP status/error bodies.
		fmt.Fprintln(os.Stderr, "N04_CURRENT_CP_REGISTERED_READ_HELD")
		os.Exit(2)
	}
	result := struct{
		Schema string `json:"schema"`
		RunID string `json:"run_id"`
		IAMSHA string `json:"iam_source_sha"`
		SharedSHA string `json:"shared_source_sha"`
		CPSHA string `json:"cp_source_sha"`
		ProviderID string `json:"provider_id"`
		InstanceID string `json:"engine_instance_id"`
		Classification string `json:"classification"`
		CPReadObserved bool `json:"cp_current_registered_read_observed"`
		NativeEngineQualified bool `json:"native_engine_qualified"`
		IndependentWitness bool `json:"independent_witness"`
		ProtectedAccepted bool `json:"protected_accepted"`
	}{Schema:"baobab.iam.n04.cp-read-observation.v1",RunID:c.RunID,IAMSHA:c.IAMSourceSHA,
		SharedSHA:c.SharedSourceSHA,CPSHA:c.CPSourceSHA,ProviderID:c.Target.ProviderID,
		InstanceID:c.Target.EngineInstanceID,
		Classification:"UNATTESTED_LIVE_CP_READ_ONLY",
		CPReadObserved:true,NativeEngineQualified:false,IndependentWitness:false,ProtectedAccepted:false}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
