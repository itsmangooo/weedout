package main

import (
	"context"
	"fmt"

	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
)

func main() {
	engine := scanner.Scanner{Parsers: builtin.Registry()}
	result, err := engine.Scan(context.Background(), model.ScanRequest{Manifests: []model.ManifestInput{{Path: "requirements.txt", Content: "requests==2.31.0"}}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d dependencies, %d findings\n", result.Stats.Dependencies, result.Stats.Matched)
}
