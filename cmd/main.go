package cmd

import (
	"fmt"
	"os"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/model"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Version = "0.0.0"

var (
	filePath       string
	configFilePath string
	reportPath     string
	vConfig        = viper.New()
)

const configFileFlag = "config"

var rootCmd = &cobra.Command{
	Use:   "ast-benchmark",
	Short: "Application Security Benchmarking Tool",
	Long:  `A command-line tool to analyze application security metrics.`,
}

func Execute() error {
	vConfig.SetEnvPrefix("Ast-Benchmark")
	vConfig.AutomaticEnv()

	cobra.OnInitialize(initialize)

	rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "Path to the config file")
	rootCmd.PersistentFlags().StringVar(&reportPath, "report-path", "", "Path to save the converted JSON report")
	cobra.CheckErr(rootCmd.MarkPersistentFlagFilename(configFileFlag, "yaml", "yml", "json"))
	rootCmd.PersistentFlags().StringVar(&filePath, "path", "", "Path to the report file")

	rootCmd.AddCommand(cxoneCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Error().Err(err).Msg("Error executing root command")
		return err
	}
	return nil
}
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
			if reportPath == "" {
				return fmt.Errorf("report path is required (use --report-path)")
			}

			err = os.WriteFile(reportPath, jsonData, 0644)
			if err != nil {
				return fmt.Errorf("failed to write JSON to file: %w", err)
			}

			return nil
		},
	}
}
