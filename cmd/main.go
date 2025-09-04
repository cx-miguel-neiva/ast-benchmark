package cmd

import (
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
	rootCmd.AddCommand(dbSeedCmd())
	rootCmd.AddCommand(benchmarkCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Error().Err(err).Msg("Error executing root command")
		return err
	}
	return nil
}
