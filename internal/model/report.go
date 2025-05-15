package model

import (
	"encoding/json"
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func ExpectedReportToJson(results map[string][]handler.EngineResult) ([]byte, error) {

	type Report struct {
		ProjectName string                 `json:"projectName"`
		Results     []handler.EngineResult `json:"results"`
	}

	var reports []Report
	for projectName, engineResults := range results {
		reports = append(reports, Report{
			ProjectName: projectName,
			Results:     engineResults,
		})
	}

	jsonData, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	return jsonData, nil
}
