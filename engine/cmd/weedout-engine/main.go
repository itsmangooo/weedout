package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/itsmangooo/weedout-engine/pkg/advisory"
	advisorypostgres "github.com/itsmangooo/weedout-engine/pkg/advisory/postgres"
	"github.com/itsmangooo/weedout-engine/pkg/api"
	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		client := http.Client{Timeout: 2 * time.Second}
		request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:8080/readyz", nil)
		response, err := client.Do(request)
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	address := os.Getenv("ENGINE_ADDR")
	if address == "" {
		address = ":8080"
	}
	service := scanner.Scanner{Parsers: builtin.Registry(), Version: version}
	var closeMirror func()
	if databaseURL := os.Getenv("ENGINE_DATABASE_URL"); databaseURL != "" {
		mirror, err := advisorypostgres.Open(context.Background(), databaseURL)
		if err != nil {
			log.Fatal(err)
		}
		service.Advisories = mirror
		closeMirror = mirror.Close
	} else if path := os.Getenv("ENGINE_ADVISORY_FILE"); path != "" {
		service.Advisories = advisory.FileSource{Path: path}
	}
	if closeMirror != nil {
		defer closeMirror()
	}
	server := &http.Server{Addr: address, Handler: api.New(service, version, slog.Default()).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("weedout engine %s listening on %s", version, address)
	log.Fatal(server.ListenAndServe())
}
