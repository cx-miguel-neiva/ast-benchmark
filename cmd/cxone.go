package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/model"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func cxoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cxone",
		Short: "Process the report with the cxone plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return fmt.Errorf("report path is required")
			}
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("report file does not exist at path: %s", filePath)
			}

			pluginName := cmd.Name()
			results, err := GetResults(filePath, pluginName)
			if err != nil {
				return fmt.Errorf("failed to process report: %w", err)
			}
			jsonData, err := model.ExpectedReportToJson(results)
			if err != nil {
				return fmt.Errorf("failed to convert report to JSON: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(reportPath), 0755); err != nil {
				return fmt.Errorf("failed to create directory for report: %w", err)
			}

			if reportPath == "" {
				return fmt.Errorf("report path is required (use --report-path)")
			}

			err = os.WriteFile(reportPath, jsonData, 0644)
			if err != nil {
				return fmt.Errorf("failed to write JSON to file: %w", err)
			}
			log.Info().Str("output", reportPath).Msg("Normalized report saved successfully.")
			return nil
		},
	}
}
