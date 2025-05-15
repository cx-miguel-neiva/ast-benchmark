package model

import (
	"encoding/json"
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func ExpectedReportToJson(results map[string][]handler.EngineResult) ([]byte, error) {
	// Definindo a estrutura para o JSON
	type Report struct {
		ProjectName string                 `json:"projectName"`
		Results     []handler.EngineResult `json:"results"` // Agora é []handler.EngineResult
	}

	// Criando o slice de relatórios
	var reports []Report
	for projectName, engineResults := range results {
		reports = append(reports, Report{
			ProjectName: projectName,
			Results:     engineResults,
		})
	}

	// Convertendo os relatórios para JSON
	jsonData, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	return jsonData, nil
}
