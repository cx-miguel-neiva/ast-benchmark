package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

type Connection struct {
	*sql.DB
}

func NewConnection(dbPath string) (*Connection, error) {
	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	schema := `
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
        UNIQUE(application_id, name)
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        version TEXT NOT NULL, -- 'vulnerable' ou 'patched'
        tool TEXT,
        FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
        UNIQUE(project_id, version)
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        engine TEXT NOT NULL,
        resource_type TEXT,
        resource TEXT,
        vulnerability_category TEXT,
        vulnerability_value TEXT,
        vulnerability_id TEXT,
        is_expected BOOLEAN NOT NULL DEFAULT 0,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &Connection{db}, nil
}

func (c *Connection) ClearAllData() error {
	_, err := c.Exec("DELETE FROM findings; DELETE FROM scans; DELETE FROM projects; DELETE FROM applications;")
	return err
}

func (c *Connection) SeedDatabase(applicationName, projectName, version, tool string, results []handler.EngineResult) (int, error) {
	tx, err := c.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var applicationID int64
	err = tx.QueryRow("INSERT INTO applications(name) VALUES(?) ON CONFLICT(name) DO UPDATE SET name=name RETURNING id", applicationName).Scan(&applicationID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert/get application: %w", err)
	}

	var projectID int64
	err = tx.QueryRow("INSERT INTO projects(application_id, name) VALUES(?, ?) ON CONFLICT(application_id, name) DO UPDATE SET name=name RETURNING id", applicationID, projectName).Scan(&projectID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert/get project: %w", err)
	}

	var scanID int64
	err = tx.QueryRow("INSERT INTO scans(project_id, version, tool) VALUES(?, ?, ?) ON CONFLICT(project_id, version) DO UPDATE SET tool=excluded.tool RETURNING id", projectID, version, tool).Scan(&scanID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert/get scan: %w", err)
	}

	stmt, err := tx.Prepare("INSERT INTO findings(scan_id, engine, resource_type, resource, vulnerability_category, vulnerability_value, vulnerability_id) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var insertedCount int
	for _, engineResult := range results {
		for _, detail := range engineResult.Details {
			_, err := stmt.Exec(scanID, engineResult.EngineType, detail.ResourceType, detail.Resource, detail.VulnerabilityCategory, detail.VulnerabilityValue, detail.ResultID)
			if err != nil {
				continue
			}
			insertedCount++
		}
	}

	return insertedCount, tx.Commit()
}

func (c *Connection) MarkExpectedFindings(suite, project string, report map[string][]handler.EngineResult) (int, error) {
	tx, err := c.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
        UPDATE findings 
        SET is_expected = 1 
        WHERE vulnerability_id = ? 
          AND scan_id IN (SELECT id FROM scans WHERE project_id = ?)
    `)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	totalMarked := 0
	if _, ok := report[project]; ok {
		projectID, err := c.getProjectID(project, suite)
		if err != nil {
			log.Warn().Str("project", project).Msg("Project not found in DB, cannot mark expected findings.")
			return 0, nil
		}

		for _, result := range report[project] {
			for _, detail := range result.Details {
				res, err := stmt.Exec(detail.ResultID, projectID)
				if err != nil {
					log.Warn().Err(err).Str("vulnerability_id", detail.ResultID).Msg("Could not execute mark finding statement")
					continue
				}
				rowsAffected, _ := res.RowsAffected()
				totalMarked += int(rowsAffected)
			}
		}
	}

	return totalMarked, tx.Commit()
}

// getProjectID returns the project ID for a given project name and suite (application name).
func (c *Connection) getProjectID(projectName, suite string) (int64, error) {
	var projectID int64
	query := `SELECT p.id FROM projects p JOIN applications a ON p.application_id = a.id WHERE p.name = ? AND a.name = ?`
	err := c.QueryRow(query, projectName, suite).Scan(&projectID)
	if err != nil {
		return 0, fmt.Errorf("could not find project ID for project '%s' and suite '%s': %w", projectName, suite, err)
	}
	return projectID, nil
}

type ProjectSummary struct {
	Name               string `json:"name"`
	VulnerabilityCount int    `json:"vulnerabilityCount"`
}

func (c *Connection) GetProjectSummaries() ([]ProjectSummary, error) {
	query := `
        SELECT
            p.name,
            COUNT(f.id)
        FROM projects p
        JOIN scans s ON p.id = s.project_id
        JOIN findings f ON s.id = f.scan_id
        WHERE s.version = 'vulnerable'
        GROUP BY p.name
        ORDER BY p.name;
    `
	rows, err := c.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []ProjectSummary
	for rows.Next() {
		var summary ProjectSummary
		if err := rows.Scan(&summary.Name, &summary.VulnerabilityCount); err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// ScoreMetrics contém os dados para o cálculo do score de benchmark.
type ScoreMetrics struct {
	ProjectName       string  `json:"projectName"`
	TruePositives     int     `json:"truePositives"`
	FalsePositives    int     `json:"falsePositives"`
	FalseNegatives    int     `json:"falseNegatives"`
	TotalExpected     int     `json:"totalExpected"`
	Sensitivity       float64 `json:"sensitivity"`       // TPR
	Specificity       float64 `json:"specificity"`       // 1 - FPR
	YoudenIndex       float64 `json:"youdenIndex"`       // (Sens + Spec) - 1
	BenchmarkAccuracy float64 `json:"benchmarkAccuracy"` // Youden * 100
}

// GetScores calcula uma lista de scores, agrupados por um determinado campo (project, tool, engine).
func (c *Connection) GetScores(groupBy, applicationName, tool, engine string) ([]ScoreMetrics, error) {
	var groupByField string
	switch groupBy {
	case "tool":
		groupByField = "s.tool"
	case "engine":
		groupByField = "f.engine"
	default: // "project" é o default
		groupByField = "p.name"
	}

	query := fmt.Sprintf(`
        WITH grouped_metrics AS (
            SELECT
                %s AS group_key,
                COUNT(DISTINCT CASE WHEN s.version = 'vulnerable' AND f.is_expected = 1 THEN f.vulnerability_id END) as tp,
                COUNT(DISTINCT CASE WHEN s.version = 'vulnerable' AND f.is_expected = 0 THEN f.vulnerability_id END) as fp,
                COUNT(DISTINCT CASE WHEN f.is_expected = 1 THEN f.vulnerability_id END) as total_expected
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN projects p ON s.project_id = p.id
            JOIN applications a ON p.application_id = a.id
            WHERE 1=1
    `, groupByField)

	var args []interface{}
	if applicationName != "" && applicationName != "all" {
		query += " AND a.name = ?"
		args = append(args, applicationName)
	}
	if tool != "" && tool != "all" {
		query += " AND s.tool = ?"
		args = append(args, tool)
	}
	if engine != "" && engine != "all" {
		query += " AND f.engine = ?"
		args = append(args, engine)
	}

	query += fmt.Sprintf(" GROUP BY %s", groupByField)

	rows, err := c.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query scores: %w", err)
	}
	defer rows.Close()

	scores := make([]ScoreMetrics, 0)
	for rows.Next() {
		var metrics ScoreMetrics
		var groupKey string
		var totalExpected int
		if err := rows.Scan(&groupKey, &metrics.TruePositives, &metrics.FalsePositives, &totalExpected); err != nil {
			return nil, fmt.Errorf("failed to scan score row: %w", err)
		}
		metrics.ProjectName = groupKey

		metrics.FalseNegatives = totalExpected - metrics.TruePositives
		if metrics.FalseNegatives < 0 {
			metrics.FalseNegatives = 0
		}

		metrics.TotalExpected = totalExpected
		if metrics.TotalExpected > 0 {
			metrics.Sensitivity = float64(metrics.TruePositives) / float64(metrics.TotalExpected)
		}

		var fpr float64
		totalFindingsInVulnerable := metrics.TruePositives + metrics.FalsePositives
		if totalFindingsInVulnerable > 0 {
			fpr = float64(metrics.FalsePositives) / float64(totalFindingsInVulnerable)
		}
		metrics.Specificity = 1.0 - fpr

		metrics.YoudenIndex = (metrics.Sensitivity + metrics.Specificity) - 1
		if metrics.YoudenIndex < 0 {
			metrics.YoudenIndex = 0
		}
		metrics.BenchmarkAccuracy = metrics.YoudenIndex * 100
		scores = append(scores, metrics)
	}

	return scores, nil
}

// GetDistinctTools retorna uma lista de todas as ferramentas únicas na base de dados.
func (c *Connection) GetDistinctTools() ([]string, error) {
	rows, err := c.Query("SELECT DISTINCT tool FROM scans ORDER BY tool")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tools []string
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

// GetDistinctEngines retorna uma lista de todos os motores únicos na base de dados.
func (c *Connection) GetDistinctEngines() ([]string, error) {
	rows, err := c.Query("SELECT DISTINCT engine FROM findings ORDER BY engine")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var engines []string
	for rows.Next() {
		var engine string
		if err := rows.Scan(&engine); err != nil {
			return nil, err
		}
		engines = append(engines, engine)
	}
	return engines, nil
}

// Percentagem de TP por Projeto
func (c *Connection) GetTruePositivePercentage(projectID int) (float64, error) {
	var tp, totalExpected int
	err := c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND f.is_expected = 1
    `, projectID).Scan(&tp)
	if err != nil {
		return 0, err
	}
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND s.version = 'patched'
    `, projectID).Scan(&totalExpected)
	if err != nil {
		return 0, err
	}
	if totalExpected == 0 {
		return 0, nil
	}
	return float64(tp) / float64(totalExpected), nil
}

// Percentagem de TP por Tool
func (c *Connection) GetTruePositivePercentageByTool(tool string) (float64, error) {
	var tp, totalExpected int
	err := c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.tool = ? AND f.is_expected = 1
    `, tool).Scan(&tp)
	if err != nil {
		return 0, err
	}
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.tool = ? AND s.version = 'patched'
    `, tool).Scan(&totalExpected)
	if err != nil {
		return 0, err
	}
	if totalExpected == 0 {
		return 0, nil
	}
	return float64(tp) / float64(totalExpected), nil
}

// Percentagem de TP por Engine
func (c *Connection) GetTruePositivePercentageByEngineWithCount(engine, repo string) (float64, int, error) {
	var tp, totalExpected, vulnCount int
	// Numerador: findings esperados encontrados em vulnerável
	err := c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE f.engine = ? AND p.name = ? AND s.version = 'vulnerable' AND f.is_expected = 1
    `, engine, repo).Scan(&tp)
	if err != nil {
		return 0, 0, err
	}
	// Denominador: findings esperados em patched
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE f.engine = ? AND p.name = ? AND s.version = 'patched' AND f.is_expected = 1
    `, engine, repo).Scan(&totalExpected)
	if err != nil {
		return 0, 0, err
	}
	// Número de vulnerabilidades em vulnerável
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE f.engine = ? AND p.name = ? AND s.version = 'vulnerable'
    `, engine, repo).Scan(&vulnCount)
	if err != nil {
		return 0, 0, err
	}
	if totalExpected == 0 {
		return 0, vulnCount, nil
	}
	return float64(tp) / float64(totalExpected), vulnCount, nil
}

func (c *Connection) GetReposByProject(project string) ([]string, error) {
	rows, err := c.Query(`
			SELECT DISTINCT name FROM projects
			WHERE name LIKE ? || '/%'
			ORDER BY name
		`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var repos []string
	for rows.Next() {
		var fullName string
		if err := rows.Scan(&fullName); err != nil {
			return nil, err
		}
		// Extrai só o nome do repositório (depois da '/')
		parts := strings.SplitN(fullName, "/", 2)
		if len(parts) == 2 {
			repos = append(repos, parts[1])
		}
	}
	return repos, nil
}

func (c *Connection) GetEnginesByRepo(repo string) ([]string, error) {
	rows, err := c.Query(`
        SELECT DISTINCT f.engine
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE p.name = ?
        ORDER BY f.engine
    `, repo)
	if err != nil {
		return []string{}, err
	}
	defer rows.Close()
	var engines []string
	for rows.Next() {
		var engine string
		if err := rows.Scan(&engine); err != nil {
			return []string{}, err
		}
		engines = append(engines, engine)
	}
	return engines, nil
}

func (c *Connection) GetProjectIDByName(repo string) (int64, error) {
	var id int64
	err := c.QueryRow("SELECT id FROM projects WHERE name = ?", repo).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (c *Connection) GetTruePositivePercentageWithCount(projectID int) (float64, int, error) {
	var tp, totalExpected, vulnCount int
	// Numerador: findings esperados encontrados em vulnerável
	err := c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND s.version = 'vulnerable' AND f.is_expected = 1
    `, projectID).Scan(&tp)
	if err != nil {
		return 0, 0, err
	}
	// Denominador: findings esperados em patched
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND s.version = 'patched' AND f.is_expected = 1
    `, projectID).Scan(&totalExpected)
	if err != nil {
		return 0, 0, err
	}
	// Número de vulnerabilidades em vulnerável
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND s.version = 'vulnerable'
    `, projectID).Scan(&vulnCount)
	if err != nil {
		return 0, 0, err
	}
	if totalExpected == 0 {
		return 0, vulnCount, nil
	}
	return float64(tp) / float64(totalExpected), vulnCount, nil
}

// Percentagem de TP por Tool + número de vulnerabilidades
func (c *Connection) GetTruePositivePercentageByToolWithCount(tool string) (float64, int, error) {
	var tp, totalExpected, vulnCount int
	// Numerador: findings esperados encontrados em vulnerável
	err := c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.tool = ? AND s.version = 'vulnerable' AND f.is_expected = 1
    `, tool).Scan(&tp)
	if err != nil {
		return 0, 0, err
	}
	// Denominador: findings esperados em patched
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.tool = ? AND s.version = 'patched' AND f.is_expected = 1
    `, tool).Scan(&totalExpected)
	if err != nil {
		return 0, 0, err
	}
	// Número de vulnerabilidades em vulnerável
	err = c.QueryRow(`
        SELECT COUNT(*) FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.tool = ? AND s.version = 'vulnerable'
    `, tool).Scan(&vulnCount)
	if err != nil {
		return 0, 0, err
	}
	if totalExpected == 0 {
		return 0, vulnCount, nil
	}
	return float64(tp) / float64(totalExpected), vulnCount, nil
}

// GetTruePositivePercentageByEngine returns the true positive percentage for a given engine.
func (c *Connection) GetTruePositivePercentageByEngine(engine string) (float64, error) {
	var tpCount, totalCount int
	query := `
        SELECT 
            SUM(CASE WHEN is_true_positive = 1 THEN 1 ELSE 0 END) as tp_count,
            COUNT(*) as total_count
        FROM vulnerabilities
        WHERE engine = ?
    `
	err := c.QueryRow(query, engine).Scan(&tpCount, &totalCount)
	if err != nil {
		return 0, err
	}
	if totalCount == 0 {
		return 0, nil
	}
	return float64(tpCount) / float64(totalCount) * 100, nil
}
