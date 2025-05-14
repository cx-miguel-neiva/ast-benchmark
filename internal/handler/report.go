package internal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/miguel-neiva/ast-benchmark/model"
)

func readFile(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}

func decodeJSON(data []byte) (map[string][]map[string]interface{}, error) {
	var report map[string][]map[string]interface{}
	err := json.Unmarshal(data, &report)
	return report, err
}

func processEntry(entry map[string]interface{}) (*model.EngineResult, error) {
	engineType, ok := entry["engineType"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'engineType' field")
	}

	delete(entry, "engineType")

	detailsJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("error serializing details: %v", err)
	}

	var detail model.VulnerabilityDetail
	if err := json.Unmarshal(detailsJSON, &detail); err != nil {
		return nil, fmt.Errorf("error decoding details: %v", err)
	}

	return &model.EngineResult{
		EngineType: engineType,
		Details:    []model.VulnerabilityDetail{detail},
	}, nil
}

func ProcessReport(filePath string) ([]model.EngineResult, error) {
	data, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	report, err := decodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	var results []model.EngineResult
	for _, entries := range report {
		for _, entry := range entries {
			engineResult, err := processEntry(entry)
			if err != nil {
				return nil, err
			}
			results = append(results, *engineResult)
		}
	}

	return results, nil
}
