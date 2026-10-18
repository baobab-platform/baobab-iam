package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHookListenerFailureReturnsError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if runHookServer(context.Background(), &http.Server{Addr: occupied.Addr().String()}) == nil {
		t.Fatal("bind failure reported success")
	}
}

func TestHookShutdownWaitsForInflightRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, release, shutdown := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("drained"))
	})}
	server.RegisterOnShutdown(func() { close(shutdown) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveHookListener(ctx, server, listener) }()
	response := make(chan string, 1)
	go func() {
		r, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			response <- "request failed"
			return
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		response <- string(b)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown never started")
	}
	select {
	case err := <-done:
		t.Fatal("server returned before request drained", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case got := <-response:
		if got != "drained" {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response did not drain")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown not joined")
	}
}

func TestHookOverallBudgetAndServiceCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "service stopped"} {
		t.Run(mode, func(t *testing.T) {
			service, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "service stopped" {
				cancel()
			}
			handler := boundedHook(service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
				w.WriteHeader(http.StatusForbidden)
			}), 20*time.Millisecond)
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, httptest.NewRequest("POST", "/", nil))
			if result.Code != http.StatusForbidden || result.Body.Len() != 0 {
				t.Fatal("expired operation emitted claims")
			}
		})
	}
}
