package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "ast-benchmark",
	Short: "Application Security Benchmarking Tool",
	Long:  `A CLI tool to benchmark and analyze application security metrics.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Initializing security analysis...")
		// Initialize and execute the scanning process
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a security scan on a project",
	Long:  `Initiates a security scan on the specified project repository.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Error reading config file:", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error executing command:", err)
		os.Exit(1)
	}
}
