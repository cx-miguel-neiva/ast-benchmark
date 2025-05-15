package cxone

import (
	"encoding/json"
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/plugins"
	"github.com/rs/zerolog/log"
)

func ParseReport(item plugins.ISourceItem) (map[string][]handler.EngineResult, error) {
	content := item.GetContent()
	if content == nil {
		err := fmt.Errorf("item %s contains empty content", item.GetID())
		log.Error().Err(err).Msg("Error processing item")
		return nil, err
	}

	contentBytes := []byte(*content)
	var raw map[string]interface{}
	if err := json.Unmarshal(contentBytes, &raw); err != nil {
		return nil, err
	}

	raw["engine"] = "cxone"

	header, ok := raw["reportHeader"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid reportHeader")
	}
	projectName, _ := header["projectName"].(string)

	resultMap := make(map[string][]handler.EngineResult)

	if iac, ok := raw["iacScanResults"]; ok {
		if arr, ok := iac.(map[string]interface{})["technology"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseIac(iac); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing IAC results")
			}
		}
	}

	if sca, ok := raw["scaScanResults"]; ok {
		if arr, ok := sca.(map[string]interface{})["packages"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseSca(sca); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing SCA results")
			}
		}
	}

	if scs, ok := raw["scsScanResults"]; ok {
		if arr, ok := scs.(map[string]interface{})["packages"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseScs(scs); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing SCS results")
			}
		}
	}

	return resultMap, nil
}
