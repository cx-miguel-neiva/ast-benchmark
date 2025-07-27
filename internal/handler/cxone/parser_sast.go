package cxone

import (
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func parseSast(data interface{}) (handler.EngineResult, error) {
	sastMap, ok := data.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid SAST data format")
	}

	resultsList, ok := sastMap["resultsList"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("missing or invalid resultsList")
	}

	var details []handler.VulnerabilityDetail
	for _, resultRaw := range resultsList {
		result, ok := resultRaw.(map[string]interface{})
		if !ok {
			continue
		}

		queryPath := handler.ToStr(result["queryPath"])
		cweId := handler.ToStr(result["cweId"])

		if queryPath == "" || cweId == "" {
			continue
		}

		resourceType := "FileName"
		category := "CWE"
		vulnID := handler.GenerateResultID(resourceType, queryPath, category, cweId)

		details = append(details, handler.VulnerabilityDetail{
			ResultID:              vulnID,
			ResourceType:          resourceType,
			Resource:              queryPath,
			VulnerabilityCategory: category,
			VulnerabilityValue:    cweId,
		})
	}

	return handler.EngineResult{
		EngineType: "SAST",
		Details:    details,
	}, nil
}
