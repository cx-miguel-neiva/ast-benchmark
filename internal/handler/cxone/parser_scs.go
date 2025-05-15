package cxone

import (
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func parseScs(scaData interface{}) (handler.EngineResult, error) {
	data, ok := scaData.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("estrutura de SCA inválida")
	}

	packages, ok := data["packages"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("lista de pacotes ausente ou inválida")
	}

	var details []handler.VulnerabilityDetail
	for _, pkgRaw := range packages {
		pkg, _ := pkgRaw.(map[string]interface{})

		name := handler.ToStr(pkg["name"])
		version := handler.ToStr(pkg["version"])
		vulns, _ := pkg["vulnerabilities"].([]interface{})

		for _, vulnRaw := range vulns {
			vuln, _ := vulnRaw.(map[string]interface{})
			severity := handler.ToStr(vuln["severity"])
			cve := handler.ToStr(vuln["cve"])

			details = append(details, handler.VulnerabilityDetail{
				ResourceType:          "Package",
				Resource:              fmt.Sprintf("%s@%s", name, version),
				VulnerabilityCategory: severity,
				VulnerabilityValue:    cve,
			})
		}
	}

	return handler.EngineResult{EngineType: "sca", Details: details}, nil
}
