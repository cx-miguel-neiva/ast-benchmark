package cxone

import (
	"fmt"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func parseSca(scaData interface{}) (handler.EngineResult, error) {
	data, ok := scaData.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid sca struct")
	}

	packages, ok := data["packages"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid packages")
	}

	var details []handler.VulnerabilityDetail
	for _, pkgRaw := range packages {
		pkg, _ := pkgRaw.(map[string]interface{})

		packageName := handler.ToStr(pkg["packageName"])
		categories, _ := pkg["packageCategory"].([]interface{})

		for _, catRaw := range categories {
			category, _ := catRaw.(map[string]interface{})
			categoryName := handler.ToStr(category["categoryName"])

			vulnCategory := ""
			if len(categoryName) >= 3 {
				vulnCategory = categoryName[:3]
			}

			vulnValue := ""
			if parts := strings.Split(categoryName, "-"); len(parts) == 2 {
				vulnValue = parts[1]
			}

			details = append(details, handler.VulnerabilityDetail{
				ResourceType:          "Package",
				Resource:              packageName,
				VulnerabilityCategory: vulnCategory,
				VulnerabilityValue:    vulnValue,
			})
		}
	}

	return handler.EngineResult{EngineType: "SCA", Details: details}, nil
}
