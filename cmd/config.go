package cmd

import (
	"fmt"
	"os"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler/cxone"
	"github.com/cx-miguel-neiva/ast-benchmark/plugins"
	"github.com/cx-miguel-neiva/ast-benchmark/utils"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func initialize() {
	if configFilePath != "" {
		cobra.CheckErr(vConfig.ReadInConfig())
		log.Info().Str("config", configFilePath).Msg("Loaded configuration file")
	}

	envPrefix := ""
	cobra.CheckErr(utils.BindFlags(rootCmd, vConfig, envPrefix))

	logLevel := zerolog.InfoLevel
	zerolog.SetGlobalLevel(logLevel)
	log.Logger = log.Logger.Level(logLevel)
}

func GetResults(path string, plugin string) (map[string][]handler.EngineResult, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}
	contentStr := string(content)

	item := &plugins.Item{
		Content: &contentStr,
		ID:      "unique-id",
		Source:  path,
	}

	var result map[string][]handler.EngineResult
	switch plugin {
	case "cxone":
		result, err = cxone.ParseReport(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed to process report")
			return nil, err // Retorna o erro se ocorrer um problema
		}

	// other plugins if needed
	// case "semgrep":
	// 	result, err = handler.ProcessSemgrepReport(item)

	// case "sonarqube":
	// 	result, err = handler.ProcessSonarQubeReport(item)

	default:
		return nil, fmt.Errorf("unsupported plugin: %s", plugin)
	}

	return result, nil
}
