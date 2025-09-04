package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/db"
	"github.com/cx-miguel-neiva/ast-benchmark/internal/normalized"
	"github.com/spf13/cobra"
)

// dbSeedCmd returns the database seed command for populating the database from benchmark files
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

			if err := os.MkdirAll(filepath.Dir(absDbPath), 0755); err != nil {
				return fmt.Errorf("failed to create database directory: %w", err)
			}

			conn, err := db.NewConnection(absDbPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if clean {
				if err := conn.ClearAllData(); err != nil {
					return fmt.Errorf("failed to clear database: %w", err)
				}
			}

			err = filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				fileName := info.Name()
				if !info.IsDir() && (fileName == "vulnerable.json" || fileName == "patched.json") {
					reports, err := normalized.ParseToMap(path)
					if err != nil {
						return nil
					}

					suite, _, version := extractContextFromPath(benchmarksDir, path)

					for projectName, results := range reports {
						_, err := conn.SeedDatabase(suite, projectName, version, tool, results)
						if err != nil {
							continue
						}
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error during initial seeding walk: %w", err)
			}

			err = filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error during marking phase walk: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "data/benchmark.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&benchmarksDir, "dir", "benchmarks", "Directory containing the benchmark suites")
	cmd.Flags().StringVar(&tool, "tool", "cxone", "The tool that generated the original reports")
	cmd.Flags().BoolVar(&clean, "clean", true, "Clear all data from the database before seeding")

	return cmd
}

// extractContextFromPath extracts suite, project, and version information from file path
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
