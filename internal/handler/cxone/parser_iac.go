package cxone

import (
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func parseIac(iacData interface{}) (handler.EngineResult, error) {
	data, ok := iacData.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid IAC structure")
	}
	techs, ok := data["technology"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("missing or invalid IAC technologies")
	}

	var details []handler.VulnerabilityDetail
	for _, techRaw := range techs {
		tech, _ := techRaw.(map[string]interface{})
		queries, _ := tech["queries"].([]interface{})
		for _, queryRaw := range queries {
			query, _ := queryRaw.(map[string]interface{})
			queryName, _ := query["queryName"].(string)
			resultsList, _ := query["resultsList"].([]interface{})
			for _, res := range resultsList {
				r, _ := res.(map[string]interface{})
				details = append(details, handler.VulnerabilityDetail{
					ResourceType:          "Filename",
					Resource:              handler.ToStr(r["fileName"]),
					VulnerabilityCategory: queryName,
					VulnerabilityValue:    handler.ToStr(r["actualValue"]),
				})
			}
		}
	}

	return handler.EngineResult{EngineType: "IAC", Details: details}, nil
}
