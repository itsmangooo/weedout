package main

import (
	"context"
	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
	"os"
)

func main() {
	content, err := os.ReadFile("package-lock.json")
	if err != nil {
		panic(err)
	}
	result, err := (scanner.Scanner{Parsers: builtin.Registry()}).Scan(context.Background(), model.ScanRequest{Manifests: []model.ManifestInput{{Path: "package-lock.json", Content: string(content)}}})
	if err != nil {
		panic(err)
	}
	if result.Stats.Blocking > 0 {
		os.Exit(1)
	}
}
