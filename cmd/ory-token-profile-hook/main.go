// Command ory-token-profile-hook serves the private authenticated Hydra hook.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:4466", "private listener; expose only to Hydra")
	profiles := flag.String("profiles", "", "governed pinned Shared JSON projection with runtime bindings")
	keyFile := flag.String("key-file", "", "private hook authentication key file")
	flag.Parse()
	file, err := os.Open(*profiles)
	if err != nil {
		log.Fatal("cannot open token profile configuration")
	}
	var config tokenprofile.Config
	err = json.NewDecoder(file).Decode(&config)
	_ = file.Close()
	if err != nil {
		log.Fatal("cannot decode token profile configuration")
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal("cannot read token hook authentication key")
	}
	hook, err := configuredHook(config, strings.TrimSpace(string(key)))
	if err != nil {
		log.Fatal("invalid token profile configuration or hook authentication key")
	}
	mux := http.NewServeMux()
	mux.Handle("/internal/ory/token-profile", hook)
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(server.ListenAndServe())
}

// configuredHook is the executable service's construction gate, not a provider
// selector. Production never falls back to mechanics-only PROVISIONED admission.
func configuredHook(config tokenprofile.Config, key string) (http.Handler, error) {
	if config.Environment == "production" {
		return ory.NewCanonicalTokenProfileHook(config, key)
	}
	return ory.NewTokenProfileHook(config, key)
}
