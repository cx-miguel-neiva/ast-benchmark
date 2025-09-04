package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/db"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/model"
	"github.com/spf13/cobra"
)

func benchmarkCmd() *cobra.Command {
	var dbPath, reportPath string
	var skipSeed, seedOnly bool

	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Process normalized reports and export comprehensive benchmark metrics",
		Long: `Process all normalized reports from the benchmarks directory to populate the database,
then export comprehensive benchmark scores and metrics as JSON.

Examples:
  # Full process: seed database + export all metrics
  ast-benchmark benchmark

  # Save to specific file
  ast-benchmark benchmark --report-path results.json

  # Only seed the database from normalized reports
  ast-benchmark benchmark --seed-only

  # Only export metrics (skip database seeding)
  ast-benchmark benchmark --skip-seed`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Se --seed-only, apenas popular a base de dados
			if seedOnly {
				return seedDatabaseFromReports(dbPath)
			}

			// Se não --skip-seed, primeiro popular a base de dados
			if !skipSeed {
				if err := seedDatabaseFromReports(dbPath); err != nil {
					return fmt.Errorf("failed to seed database: %w", err)
				}
			}

			// Determinar onde salvar o output
			outputFile := reportPath

			// Exportar métricas da base de dados
			return exportComprehensiveMetrics(dbPath, outputFile)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "data/benchmark.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&reportPath, "report-path", "", "Path to save the JSON output (if empty, prints to stdout)")
	cmd.Flags().BoolVar(&skipSeed, "skip-seed", false, "Skip database seeding step")
	cmd.Flags().BoolVar(&seedOnly, "seed-only", false, "Only seed database, don't export metrics")

	return cmd
}

// seedDatabaseFromReports processes all normalized reports and populates the database
func seedDatabaseFromReports(dbPath string) error {
	absDbPath, err := filepath.Abs(dbPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for db: %w", err)
	}

	conn, err := db.NewConnection(absDbPath)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer conn.Close()

	if err := conn.ClearAllData(); err != nil {
		return fmt.Errorf("failed to clear existing data: %w", err)
	}

	benchmarksDir := "benchmarks"
	var reportFiles []string

	err = filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".json") && (strings.Contains(path, "patched.json") || strings.Contains(path, "vulnerable.json")) {
			reportFiles = append(reportFiles, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to scan benchmarks directory: %w", err)
	}

	for _, filePath := range reportFiles {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var reports []struct {
			ProjectName string                 `json:"projectName"`
			Results     []handler.EngineResult `json:"results"`
		}

		if err := json.Unmarshal(content, &reports); err != nil {
			continue
		}

		version := "vulnerable"
		if strings.Contains(filePath, "patched.json") {
			version = "patched"
		}

		parts := strings.Split(filePath, string(os.PathSeparator))
		applicationName := "unknown"
		if len(parts) >= 3 {
			applicationName = parts[len(parts)-2]
		}

		for _, report := range reports {
			_, err := conn.SeedDatabase(applicationName, report.ProjectName, version, "cxone", report.Results)
			if err != nil {
				continue
			}
		}
	}

	return nil
}

// exportComprehensiveMetrics exports comprehensive metrics from the database
func exportComprehensiveMetrics(dbPath, outputPath string) error {
	if dbPath == "" {
		return fmt.Errorf("database path is required (use --db)")
	}

	absDbPath, err := filepath.Abs(dbPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for db: %w", err)
	}

	if _, err := os.Stat(absDbPath); os.IsNotExist(err) {
		return fmt.Errorf("database file does not exist at path: %s", absDbPath)
	}

	conn, err := db.NewConnection(absDbPath)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer conn.Close()

	summaries, err := conn.GetProjectSummaries()
	if err != nil {
		summaries = []db.ProjectSummary{}
	}

	engines, err := conn.GetDistinctEngines()
	if err != nil {
		engines = []string{}
	}

	var repositories []model.RepositoryBenchmark
	enginesScore := make(map[string]model.EngineScore)

	// Process each repository
	for _, summary := range summaries {
		// projectID, err := conn.GetProjectIDByName(summary.Name)
		// if err != nil {
		//	continue
		// }

		// tpPercentage, vulnCount, err := conn.GetTruePositivePercentageWithCount(int(projectID))
		// if err != nil {
		//	continue
		// }

		// tpAbsolute := int(tpPercentage * float64(vulnCount))

		repoEngines := make(map[string]model.EngineMetrics)
		var repoPercentages []float64
		var repoVulnCount, repoTpCount int

		for _, eng := range engines {
			tpPercEngine, vulnCountEngine, err := conn.GetTruePositivePercentageByEngineWithCount(eng, summary.Name)
			if err != nil {
				continue
			}

			tpAbsEngine := int(tpPercEngine * float64(vulnCountEngine))

			if vulnCountEngine > 0 {
				repoPercentages = append(repoPercentages, tpPercEngine*100)
				repoVulnCount += vulnCountEngine
				repoTpCount += tpAbsEngine
			}

			repoEngines[eng] = model.EngineMetrics{
				TpPercentage:            tpPercEngine * 100,
				DetectedVulnerabilities: tpAbsEngine,
				VulnerabilityCount:      vulnCountEngine,
			}
		}

		var allTpPercentage float64
		if len(repoPercentages) > 0 {
			sum := 0.0
			for _, perc := range repoPercentages {
				sum += perc
			}
			allTpPercentage = sum / float64(len(repoPercentages))
		}

		repositories = append(repositories, model.RepositoryBenchmark{
			RepositoryName: summary.Name,
			All: model.RepositoryScore{
				TpPercentage:            allTpPercentage,
				DetectedVulnerabilities: repoTpCount,
				VulnerabilityCount:      repoVulnCount,
			},
			Engines: repoEngines,
		})
	}

	// Calculate engine scores (average percentage across repositories)
	for _, eng := range engines {
		var totalPercentage float64
		var repoCount int

		// Calculate average percentage for this engine
		for _, repo := range repositories {
			if engData, exists := repo.Engines[eng]; exists {
				totalPercentage += engData.TpPercentage
				repoCount++
			}
		}

		// Calculate average percentage
		var avgPercentage float64
		if repoCount > 0 {
			avgPercentage = totalPercentage / float64(repoCount)
		}

		enginesScore[eng] = model.EngineScore{
			TpPercentage: avgPercentage,
		}
	}

	// Calculate overall score (average of repository percentages)
	var overallTpPercentage float64
	if len(repositories) > 0 {
		var totalPercentage float64
		for _, repo := range repositories {
			totalPercentage += repo.All.TpPercentage
		}
		overallTpPercentage = totalPercentage / float64(len(repositories))
	}

	// Create final report
	report := model.BenchmarkReport{
		OverallScore: model.OverallScore{
			TpPercentage:      overallTpPercentage,
			TotalRepositories: len(repositories),
		},
		EnginesScore: enginesScore,
		Repositories: repositories,
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data to JSON: %w", err)
	}

	// Always print to terminal
	fmt.Println(string(jsonData))

	// Also save to file if path is provided
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for output: %w", err)
		}
		err = os.WriteFile(outputPath, jsonData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write JSON to file: %w", err)
		}
	}

	return nil
}
