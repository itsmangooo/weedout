package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"net/http"
)

func scan(ctx context.Context, endpoint string, request model.ScanRequest) (model.ScanResult, error) {
	payload, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/scan", bytes.NewReader(payload))
	if err != nil {
		return model.ScanResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return model.ScanResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return model.ScanResult{}, fmt.Errorf("engine returned %s", response.Status)
	}
	var result model.ScanResult
	err = json.NewDecoder(response.Body).Decode(&result)
	return result, err
}
func main() {}
