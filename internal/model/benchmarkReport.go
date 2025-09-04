package model

// BenchmarkReport represents the complete benchmark report structure
type BenchmarkReport struct {
	OverallScore OverallScore           `json:"overallScore"`
	EnginesScore map[string]EngineScore `json:"enginesScore"`
	Repositories []RepositoryBenchmark  `json:"repositories"`
}

// OverallScore represents the overall benchmark statistics
type OverallScore struct {
	TpPercentage      float64 `json:"tpPercentage"`
	TotalRepositories int     `json:"totalRepositories"`
}

// EngineScore represents the score for a specific engine
type EngineScore struct {
	TpPercentage float64 `json:"tpPercentage"`
}

// RepositoryBenchmark represents the benchmark data for a single repository
type RepositoryBenchmark struct {
	RepositoryName string                   `json:"repositoryName"`
	All            RepositoryScore          `json:"all"`
	Engines        map[string]EngineMetrics `json:"engines"`
}

// RepositoryScore represents the overall score for a repository
type RepositoryScore struct {
	TpPercentage            float64 `json:"tpPercentage"`
	DetectedVulnerabilities int     `json:"detectedVulnerabilities"`
	VulnerabilityCount      int     `json:"vulnerabilityCount"`
}

// EngineMetrics represents the metrics for a specific engine in a repository
type EngineMetrics struct {
	TpPercentage            float64 `json:"tpPercentage"`
	DetectedVulnerabilities int     `json:"detectedVulnerabilities"`
	VulnerabilityCount      int     `json:"vulnerabilityCount"`
}
