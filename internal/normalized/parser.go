package normalized

import (
    "encoding/json"
    "os"

    "github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

type Report struct {
    ProjectName string                 `json:"projectName"`
    Results     []handler.EngineResult `json:"results"`
}

// Parse retorna diretamente a lista de resultados do primeiro relatório encontrado no ficheiro.
func Parse(filePath string) ([]handler.EngineResult, error) {
    fileBytes, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    var reports []Report
    if err := json.Unmarshal(fileBytes, &reports); err != nil {
        return nil, err
    }

    if len(reports) > 0 {
        return reports[0].Results, nil
    }

    return []handler.EngineResult{}, nil
}

// ParseToMap retorna um mapa de projectName para uma lista de resultados.
// Necessário para a função MarkExpectedFindings.
func ParseToMap(filePath string) (map[string][]handler.EngineResult, error) {
    fileBytes, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    var reports []Report
    if err := json.Unmarshal(fileBytes, &reports); err != nil {
        return nil, err
    }

    resultMap := make(map[string][]handler.EngineResult)
    for _, report := range reports {
        resultMap[report.ProjectName] = report.Results
    }

    return resultMap, nil
}