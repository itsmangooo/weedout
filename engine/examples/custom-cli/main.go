package main

import (
	"context"
	"encoding/json"
	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
	"os"
)

func main() {
	var request model.ScanRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		panic(err)
	}
	result, err := (scanner.Scanner{Parsers: builtin.Registry()}).Scan(context.Background(), request)
	if err != nil {
		panic(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
