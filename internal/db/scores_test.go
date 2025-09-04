package db

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func TestTruePositiveCalculations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	conn, err := NewConnection(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer conn.Close()

	setupTestData(t, conn)

	t.Run("TestGetTruePositivePercentageWithCount", func(t *testing.T) {
		projectID, err := conn.GetProjectIDByName("MAD-Goat-Project/mad-deployment-service")
		if err != nil {
			t.Fatalf("Failed to get project ID: %v", err)
		}

		tpPercentage, vulnCount, err := conn.GetTruePositivePercentageWithCount(int(projectID))
		if err != nil {
			t.Fatalf("Failed to get TP percentage: %v", err)
		}

		t.Logf("Project: mad-deployment-service")
		t.Logf("TP Percentage: %.2f%%", tpPercentage*100)
		t.Logf("Vulnerability Count: %d", vulnCount)
		t.Logf("True Positives: %d", int(tpPercentage*float64(vulnCount)))
		if tpPercentage < 0 || tpPercentage > 1 {
			t.Errorf("TP percentage should be between 0 and 1, got: %f", tpPercentage)
		}

		if vulnCount <= 0 {
			t.Errorf("Vulnerability count should be positive, got: %d", vulnCount)
		}
	})

	t.Run("TestGetTruePositivePercentageByEngine", func(t *testing.T) {
		engines := []string{"SCA", "IAC", "SAST"}

		for _, engine := range engines {
			tpPercentage, vulnCount, err := conn.GetTruePositivePercentageByEngineWithCount(engine, "MAD-Goat-Project/mad-deployment-service")
			if err != nil {
				t.Logf("Engine %s: No data or error: %v", engine, err)
				continue
			}

			t.Logf("Engine: %s", engine)
			t.Logf("TP Percentage: %.2f%%", tpPercentage*100)
			t.Logf("Vulnerability Count: %d", vulnCount)
			t.Logf("True Positives: %d", int(tpPercentage*float64(vulnCount)))

			if tpPercentage < 0 || tpPercentage > 1 {
				t.Errorf("Engine %s: TP percentage should be between 0 and 1, got: %f", engine, tpPercentage)
			}
		}
	})

	t.Run("TestCompareVulnerableVsPatchedFindings", func(t *testing.T) {
		vulnerableFindings, err := conn.getVulnerabilityIDsByProjectAndType("MAD-Goat-Project/mad-deployment-service", "vulnerable")
		if err != nil {
			t.Fatalf("Failed to get vulnerable findings: %v", err)
		}

		patchedFindings, err := conn.getVulnerabilityIDsByProjectAndType("MAD-Goat-Project/mad-deployment-service", "patched")
		if err != nil {
			t.Fatalf("Failed to get patched findings: %v", err)
		}

		t.Logf("Vulnerable findings count: %d", len(vulnerableFindings))
		t.Logf("Patched findings count: %d", len(patchedFindings))

		intersection := make(map[string]bool)
		for _, vulnID := range vulnerableFindings {
			intersection[vulnID] = false
		}

		commonCount := 0
		for _, patchedID := range patchedFindings {
			if _, exists := intersection[patchedID]; exists {
				intersection[patchedID] = true
				commonCount++
			}
		}

		t.Logf("Common vulnerability IDs (True Positives): %d", commonCount)

		if len(patchedFindings) > 0 {
			tpPercentage := float64(commonCount) / float64(len(patchedFindings))
			t.Logf("Manual TP calculation (correct way): %.2f%%", tpPercentage*100)
		}

		t.Logf("Sample vulnerable IDs:")
		for i, id := range vulnerableFindings {
			if i >= 5 {
				break
			}
			t.Logf("  %s", id)
		}

		t.Logf("Sample patched IDs:")
		for i, id := range patchedFindings {
			if i >= 5 {
				break
			}
			t.Logf("  %s", id)
		}
	})

	t.Run("TestAllRepositoriesOverall", func(t *testing.T) {
		// Test para calcular o "all" geral (média de todos os repositórios)
		summaries, err := conn.GetProjectSummaries()
		if err != nil {
			t.Fatalf("Failed to get project summaries: %v", err)
		}

		var repositoryPercentages []float64
		var totalTPs, totalVulns int

		for _, summary := range summaries {
			projectID, err := conn.GetProjectIDByName(summary.Name)
			if err != nil {
				continue
			}

			tpPercentage, vulnCount, err := conn.GetTruePositivePercentageWithCount(int(projectID))
			if err != nil {
				continue
			}

			if vulnCount > 0 {
				repositoryPercentages = append(repositoryPercentages, tpPercentage*100)
				totalTPs += int(tpPercentage * float64(vulnCount))
				totalVulns += vulnCount
			}

			t.Logf("Repository %s: %.2f%% TP", summary.Name, tpPercentage*100)
		}

		// Método 1: Média das percentagens dos repositórios
		var overallByAverage float64
		if len(repositoryPercentages) > 0 {
			sum := 0.0
			for _, percentage := range repositoryPercentages {
				sum += percentage
			}
			overallByAverage = sum / float64(len(repositoryPercentages))
		}

		// Método 2: Total de TPs / Total de vulnerabilidades
		var overallByTotal float64
		if totalVulns > 0 {
			overallByTotal = (float64(totalTPs) / float64(totalVulns)) * 100
		}

		t.Logf("Overall TP by average of repositories: %.2f%%", overallByAverage)
		t.Logf("Overall TP by total calculation: %.2f%%", overallByTotal)
		t.Logf("Total repositories: %d", len(repositoryPercentages))
	})

	t.Run("TestAllEnginesGlobal", func(t *testing.T) {
		// Test para calcular a média global de cada engine
		engines, err := conn.GetDistinctEngines()
		if err != nil {
			t.Fatalf("Failed to get engines: %v", err)
		}

		summaries, err := conn.GetProjectSummaries()
		if err != nil {
			t.Fatalf("Failed to get project summaries: %v", err)
		}

		globalEngineStats := make(map[string][]float64)
		for _, eng := range engines {
			globalEngineStats[eng] = []float64{}
		}

		// Recolher percentagens de cada engine por repositório
		for _, summary := range summaries {
			for _, eng := range engines {
				tpPercentage, vulnCount, err := conn.GetTruePositivePercentageByEngineWithCount(eng, summary.Name)
				if err != nil {
					continue
				}

				if vulnCount > 0 {
					globalEngineStats[eng] = append(globalEngineStats[eng], tpPercentage*100)
				}
			}
		}

		// Calcular média para cada engine
		for _, eng := range engines {
			percentages := globalEngineStats[eng]
			var averagePercentage float64
			totalRepos := len(percentages)

			if totalRepos > 0 {
				sum := 0.0
				for _, percentage := range percentages {
					sum += percentage
				}
				averagePercentage = sum / float64(totalRepos)
			}

			t.Logf("Engine %s global average: %.2f%% (from %d repositories)", eng, averagePercentage, totalRepos)
		}
	})

	t.Run("TestAllWithinRepository", func(t *testing.T) {
		// Test para calcular o "all" dentro de um repositório (média dos engines)
		projectName := "MAD-Goat-Project/mad-deployment-service"
		engines := []string{"IAC", "SCA"}

		var repositoryEnginePercentages []float64
		var totalVulnCountForRepo, totalTpCountForRepo int

		t.Logf("Testing repository: %s", projectName)

		for _, eng := range engines {
			tpPercentage, vulnCount, err := conn.GetTruePositivePercentageByEngineWithCount(eng, projectName)
			if err != nil {
				t.Logf("Engine %s: No data or error: %v", eng, err)
				continue
			}

			if vulnCount > 0 {
				repositoryEnginePercentages = append(repositoryEnginePercentages, tpPercentage*100)
				totalVulnCountForRepo += vulnCount
				totalTpCountForRepo += int(tpPercentage * float64(vulnCount))
			}

			t.Logf("Engine %s: %.2f%% TP (%d vulnerabilities)", eng, tpPercentage*100, vulnCount)
		}

		// Calcular "all" como média das percentagens dos engines deste repositório
		var allTpPercentage float64
		if len(repositoryEnginePercentages) > 0 {
			sum := 0.0
			for _, percentage := range repositoryEnginePercentages {
				sum += percentage
			}
			allTpPercentage = sum / float64(len(repositoryEnginePercentages))
		}

		t.Logf("Repository %s 'all' (average of engines): %.2f%%", projectName, allTpPercentage)
		t.Logf("Repository %s total vulnerabilities: %d", projectName, totalVulnCountForRepo)
		t.Logf("Repository %s total TPs: %d", projectName, totalTpCountForRepo)

		// Verificar se a média faz sentido
		if len(repositoryEnginePercentages) > 0 && (allTpPercentage < 0 || allTpPercentage > 100) {
			t.Errorf("Repository 'all' percentage should be between 0 and 100, got: %f", allTpPercentage)
		}
	})

	t.Run("TestEngineAverageComparison", func(t *testing.T) {
		// Test para comparar diferentes métodos de cálculo por engine
		projectName := "MAD-Goat-Project/mad-deployment-service"
		engine := "IAC"

		// Método 1: Usando a função específica
		tpPercentage, vulnCount, err := conn.GetTruePositivePercentageByEngineWithCount(engine, projectName)
		if err != nil {
			t.Fatalf("Failed to get TP percentage by engine: %v", err)
		}

		// Método 2: Cálculo manual direto
		vulnerableIDs, err := conn.getVulnerabilityIDsByProjectEngineAndType(projectName, engine, "vulnerable")
		if err != nil {
			t.Fatalf("Failed to get vulnerable IDs: %v", err)
		}

		patchedIDs, err := conn.getVulnerabilityIDsByProjectEngineAndType(projectName, engine, "patched")
		if err != nil {
			t.Fatalf("Failed to get patched IDs: %v", err)
		}

		// Calcular interseção manual
		commonCount := 0
		patchedMap := make(map[string]bool)
		for _, id := range patchedIDs {
			patchedMap[id] = true
		}

		for _, vulnID := range vulnerableIDs {
			if patchedMap[vulnID] {
				commonCount++
			}
		}

		var manualTpPercentage float64
		if len(patchedIDs) > 0 {
			manualTpPercentage = float64(commonCount) / float64(len(patchedIDs))
		}

		t.Logf("Engine %s function result: %.2f%% (%d vulnerabilities)", engine, tpPercentage*100, vulnCount)
		t.Logf("Engine %s manual calculation: %.2f%% (%d patched, %d vulnerable, %d common)",
			engine, manualTpPercentage*100, len(patchedIDs), len(vulnerableIDs), commonCount)

		// Verificar se os valores coincidem
		if math.Abs(tpPercentage-manualTpPercentage) > 0.001 {
			t.Errorf("TP percentages don't match: function=%.3f, manual=%.3f", tpPercentage, manualTpPercentage)
		}
	})
}

// Helper function para criar dados de teste
func setupTestData(t *testing.T, conn *Connection) {
	// Limpar dados existentes
	err := conn.ClearAllData()
	if err != nil {
		t.Fatalf("Failed to clear test data: %v", err)
	}

	// Inserir dados de teste baseados nos ficheiros reais
	testData := getTestReportData()

	for _, data := range testData {
		// SeedDatabase espera: applicationName, projectName, version, tool, results
		_, err := conn.SeedDatabase(data.suite, data.projectName, data.scanType, data.tool, data.report[data.projectName])
		if err != nil {
			t.Fatalf("Failed to save test report: %v", err)
		}
	}
}

type testReportData struct {
	suite       string
	projectType string
	projectName string
	scanType    string
	tool        string
	report      map[string][]handler.EngineResult
}

func getTestReportData() []testReportData {
	// Dados baseados no ficheiro patched.json que vimos
	patchedReport := map[string][]handler.EngineResult{
		"MAD-Goat-Project/mad-deployment-service": {
			{
				EngineType: "IAC",
				Details: []handler.VulnerabilityDetail{
					{
						ResultID:              "328a149648250c84434360e0bd9b013e",
						ResourceType:          "Filename",
						Resource:              "/Dockerfile",
						VulnerabilityCategory: "Missing User Instruction",
						VulnerabilityValue:    "The 'Dockerfile' does not contain any 'USER' instruction",
					},
					{
						ResultID:              "328a149648250c84434360e0bd9b013d",
						ResourceType:          "Filename",
						Resource:              "/Dockerfile",
						VulnerabilityCategory: "Missing User Instruction",
						VulnerabilityValue:    "The 'Dockerfile' does not contain any 'USER' instruction",
					},
				},
			},
			{
				EngineType: "SCA",
				Details: []handler.VulnerabilityDetail{
					{
						ResultID:              "8ec311ea1d3b90f98ece6d9d8708cfd0",
						ResourceType:          "Package",
						Resource:              "org.apache.logging.log4j:log4j-core",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "502",
					},
					{
						ResultID:              "b1d49eb66b250abb3c7b6b526e77f646",
						ResourceType:          "Package",
						Resource:              "org.apache.logging.log4j:log4j-core",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "74",
					},
					{
						ResultID:              "37c1ecbd4af799dca432c019c4d3dbe9",
						ResourceType:          "Package",
						Resource:              "org.apache.logging.log4j:log4j-core",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "20",
					},
				},
			},
		},
	}

	// Dados simulados para vulnerable (alguns iguais aos patched para testar TPs)
	vulnerableReport := map[string][]handler.EngineResult{
		"MAD-Goat-Project/mad-deployment-service": {
			{
				EngineType: "IAC",
				Details: []handler.VulnerabilityDetail{
					{
						ResultID:              "328a149648250c84434360e0bd9b013e", // Mesmo ID - deve ser TP
						ResourceType:          "Filename",
						Resource:              "/Dockerfile",
						VulnerabilityCategory: "Missing User Instruction",
						VulnerabilityValue:    "The 'Dockerfile' does not contain any 'USER' instruction",
					},
					{
						ResultID:              "different_vulnerability_id_123", // ID diferente - não é TP
						ResourceType:          "Filename",
						Resource:              "/Dockerfile",
						VulnerabilityCategory: "Some Other Issue",
						VulnerabilityValue:    "Some other vulnerability",
					},
				},
			},
			{
				EngineType: "SCA",
				Details: []handler.VulnerabilityDetail{
					{
						ResultID:              "8ec311ea1d3b90f98ece6d9d8708cfd0", // Mesmo ID - deve ser TP
						ResourceType:          "Package",
						Resource:              "org.apache.logging.log4j:log4j-core",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "502",
					},
					{
						ResultID:              "b1d49eb66b250abb3c7b6b526e77f646", // Mesmo ID - deve ser TP
						ResourceType:          "Package",
						Resource:              "org.apache.logging.log4j:log4j-core",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "74",
					},
					{
						ResultID:              "unique_vulnerable_only_id", // ID só no vulnerable - não é TP
						ResourceType:          "Package",
						Resource:              "some.other:package",
						VulnerabilityCategory: "CWE",
						VulnerabilityValue:    "999",
					},
				},
			},
		},
	}

	return []testReportData{
		{
			suite:       "madGoat",
			projectType: "deployment-service",
			projectName: "MAD-Goat-Project/mad-deployment-service",
			scanType:    "patched",
			tool:        "cxone",
			report:      patchedReport,
		},
		{
			suite:       "madGoat",
			projectType: "deployment-service",
			projectName: "MAD-Goat-Project/mad-deployment-service",
			scanType:    "vulnerable",
			tool:        "cxone",
			report:      vulnerableReport,
		},
	}
}

// Helper function para obter vulnerability IDs por projeto e tipo de scan
func (c *Connection) getVulnerabilityIDsByProjectAndType(projectName, scanType string) ([]string, error) {
	query := `
		SELECT DISTINCT f.vulnerability_id
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE p.name = ? AND s.version = ?
		ORDER BY f.vulnerability_id
	`

	rows, err := c.Query(query, projectName, scanType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilityIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		vulnerabilityIDs = append(vulnerabilityIDs, id)
	}

	return vulnerabilityIDs, rows.Err()
}

// Helper function para obter vulnerability IDs por projeto, engine e tipo de scan
func (c *Connection) getVulnerabilityIDsByProjectEngineAndType(projectName, engine, scanType string) ([]string, error) {
	query := `
		SELECT DISTINCT f.vulnerability_id
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE p.name = ? AND f.engine = ? AND s.version = ?
		ORDER BY f.vulnerability_id
	`

	rows, err := c.Query(query, projectName, engine, scanType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilityIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		vulnerabilityIDs = append(vulnerabilityIDs, id)
	}

	return vulnerabilityIDs, rows.Err()
}
