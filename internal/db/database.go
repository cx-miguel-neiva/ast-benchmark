package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	_ "modernc.org/sqlite"
)

type Connection struct {
	*sql.DB
}

// NewConnection creates and initializes a new database connection with schema
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

// ClearAllData removes all data from the database tables
func (c *Connection) ClearAllData() error {
	_, err := c.Exec("DELETE FROM findings; DELETE FROM scans; DELETE FROM projects; DELETE FROM applications;")
	return err
}

// SeedDatabase inserts findings data into the database
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

// GetDistinctTools returns a list of all unique tools in the database
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

// GetTruePositivePercentageWithCount calculates the true positive percentage for a project
func (c *Connection) GetTruePositivePercentageWithCount(projectID int) (float64, int, error) {
	var tp int
	err := c.QueryRow(`
        SELECT COUNT(DISTINCT f_patch.vulnerability_id) 
        FROM findings f_patch
        JOIN scans s_patch ON f_patch.scan_id = s_patch.id
        WHERE s_patch.project_id = ? AND s_patch.version = 'patched'
        AND EXISTS (
            SELECT 1 FROM findings f_vuln
            JOIN scans s_vuln ON f_vuln.scan_id = s_vuln.id
            WHERE s_vuln.project_id = ? AND s_vuln.version = 'vulnerable'
            AND f_vuln.vulnerability_id = f_patch.vulnerability_id
        )
    `, projectID, projectID).Scan(&tp)
	if err != nil {
		return 0, 0, err
	}

	var totalExpected int
	err = c.QueryRow(`
        SELECT COUNT(DISTINCT f.vulnerability_id) 
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE s.project_id = ? AND s.version = 'patched'
    `, projectID).Scan(&totalExpected)
	if err != nil {
		return 0, 0, err
	}

	var vulnCount int
	err = c.QueryRow(`
        SELECT COUNT(DISTINCT f.vulnerability_id) 
        FROM findings f
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

// GetTruePositivePercentageByEngineWithCount calculates the true positive percentage for a specific engine and repository
func (c *Connection) GetTruePositivePercentageByEngineWithCount(engine, repo string) (float64, int, error) {
	var tp int
	err := c.QueryRow(`
        SELECT COUNT(DISTINCT f_patch.vulnerability_id)
        FROM findings f_patch
        JOIN scans s_patch ON f_patch.scan_id = s_patch.id
        JOIN projects p ON s_patch.project_id = p.id
        WHERE f_patch.engine = ? AND p.name = ? AND s_patch.version = 'patched'
        AND EXISTS (
            SELECT 1 FROM findings f_vuln
            JOIN scans s_vuln ON f_vuln.scan_id = s_vuln.id
            JOIN projects p2 ON s_vuln.project_id = p2.id
            WHERE f_vuln.engine = ? AND p2.name = ? AND s_vuln.version = 'vulnerable'
            AND f_vuln.vulnerability_id = f_patch.vulnerability_id
        )
    `, engine, repo, engine, repo).Scan(&tp)
	if err != nil {
		return 0, 0, err
	}

	var totalExpected int
	err = c.QueryRow(`
        SELECT COUNT(DISTINCT f.vulnerability_id)
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE f.engine = ? AND p.name = ? AND s.version = 'patched'
    `, engine, repo).Scan(&totalExpected)
	if err != nil {
		return 0, 0, err
	}

	var vulnCount int
	err = c.QueryRow(`
        SELECT COUNT(DISTINCT f.vulnerability_id)
        FROM findings f
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
