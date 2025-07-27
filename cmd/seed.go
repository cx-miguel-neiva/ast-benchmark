package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/db"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/normalized"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func dbSeedCmd() *cobra.Command {
	var dbPath, benchmarksDir, tool string
	var clean bool

	cmd := &cobra.Command{
		Use:   "db:seed",
		Short: "Clears and seeds the database from the normalized reports in the benchmarks directory.",
		Long: `This command walks the specified benchmarks directory, loading the vulnerable.json
and patched.json files into a relational SQLite database. It then marks the findings from patched.json as 'expected'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absDbPath, err := filepath.Abs(dbPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for db: %w", err)
			}
			log.Info().Str("db_path", absDbPath).Msg("Resolved database path")

			if err := os.MkdirAll(filepath.Dir(absDbPath), 0755); err != nil {
				return fmt.Errorf("failed to create database directory: %w", err)
			}

			conn, err := db.NewConnection(absDbPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if clean {
				log.Info().Msg("Clearing all existing data from the database...")
				if err := conn.ClearAllData(); err != nil {
					return fmt.Errorf("failed to clear database: %w", err)
				}
			}

			log.Info().Msg("--- Step 1: Seeding findings from all .json files ---")
			err = filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				fileName := info.Name()
				if !info.IsDir() && (fileName == "vulnerable.json" || fileName == "patched.json") {
					// A SOLUÇÃO: Usamos ParseToMap para obter o nome do projeto diretamente do JSON.
					reports, err := normalized.ParseToMap(path)
					if err != nil {
						log.Error().Err(err).Str("file", path).Msg("Failed to parse normalized report")
						return nil
					}

					suite, _, version := extractContextFromPath(benchmarksDir, path)

					// Itera sobre os projetos encontrados no ficheiro JSON (geralmente apenas um)
					for projectName, results := range reports {
						count, err := conn.SeedDatabase(suite, projectName, version, tool, results)
						if err != nil {
							log.Error().Err(err).Str("project", projectName).Msg("Failed to seed data")
						} else {
							log.Info().Int("count", count).Str("project", projectName).Msg("Seeded findings.")
						}
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error during initial seeding walk: %w", err)
			}

			log.Info().Msg("--- Step 2: Marking expected findings based on patched.json files ---")
			err = filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && info.Name() == "patched.json" {
					report, err := normalized.ParseToMap(path)
					if err != nil {
						log.Error().Err(err).Str("file", path).Msg("Failed to parse patched report for marking")
						return nil
					}

					suite, _, _ := extractContextFromPath(benchmarksDir, path)

					// Itera sobre os projetos para marcar os findings
					for projectName, results := range report {
						// Criamos um mapa para a função MarkExpectedFindings
						reportForMarking := map[string][]handler.EngineResult{projectName: results}
						count, err := conn.MarkExpectedFindings(suite, projectName, reportForMarking)
						if err != nil {
							log.Error().Err(err).Str("project", projectName).Msg("Failed to mark expected findings")
						} else {
							log.Info().Int("count", count).Str("project", projectName).Msg("Marked expected findings.")
						}
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error during marking phase walk: %w", err)
			}

			log.Info().Msg("Database seeding process finished successfully.")
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "data/benchmark.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&benchmarksDir, "dir", "benchmarks", "Directory containing the benchmark suites")
	cmd.Flags().StringVar(&tool, "tool", "cxone", "The tool that generated the original reports")
	cmd.Flags().BoolVar(&clean, "clean", true, "Clear all data from the database before seeding")

	return cmd
}

func extractContextFromPath(baseDir, filePath string) (suite, project, version string) {
	relPath, err := filepath.Rel(baseDir, filePath)
	if err != nil {
		return "", "", ""
	}

	parts := strings.Split(relPath, string(os.PathSeparator))
	if len(parts) < 3 {
		return "", "", ""
	}

	suite = parts[0]
	project = parts[1]
	version = strings.TrimSuffix(parts[2], ".json")
	return
}
