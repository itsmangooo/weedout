package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/advisory"
	"github.com/itsmangooo/weedout-engine/pkg/api"
	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
)

type unavailableSource struct{}

func (unavailableSource) Advisories(context.Context, []advisory.Query) ([]model.Advisory, error) {
	return nil, nil
}
func (unavailableSource) Ping(context.Context) error { return errors.New("mirror unavailable") }

func TestVersionedScanAPI(t *testing.T) {
	server := httptest.NewServer(api.New(scanner.Scanner{Parsers: builtin.Registry()}, "test", nil).Handler())
	defer server.Close()
	response, err := http.Post(server.URL+"/v1/scan", "application/json", strings.NewReader(`{"schema_version":"v1","manifests":[{"path":"requirements.txt","content":"requests==2.31.0"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("scan responses must not be cached")
	}
}

func TestReadinessReflectsAdvisoryProvider(t *testing.T) {
	server := httptest.NewServer(api.New(scanner.Scanner{
		Parsers:    builtin.Registry(),
		Advisories: unavailableSource{},
	}, "test", nil).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", response.StatusCode)
	}
}
