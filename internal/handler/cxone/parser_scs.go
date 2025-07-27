package cxone

import (
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func parseScs(scsData interface{}) (handler.EngineResult, error) {
	data, ok := scsData.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("estrutura de SCS inválida")
	}

	resultsList, ok := data["resultsList"].([]interface{})
	if !ok {
		return handler.EngineResult{EngineType: "SCS", Details: []handler.VulnerabilityDetail{}}, nil
	}

	var details []handler.VulnerabilityDetail
	for _, resRaw := range resultsList {
		res, _ := resRaw.(map[string]interface{})

		resourceType := "SupplyChain"
		category := handler.ToStr(res["type"])
		value := handler.ToStr(res["details"])

		resource := category

		resultID := handler.GenerateResultID(resourceType, resource, category, value)

		details = append(details, handler.VulnerabilityDetail{
			ResultID:              resultID,
			ResourceType:          resourceType,
			Resource:              resource,
			VulnerabilityCategory: category,
			VulnerabilityValue:    value,
		})
	}

	return handler.EngineResult{EngineType: "SCS", Details: details}, nil
}
