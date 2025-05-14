package internal

type VulnerabilityDetail struct {
	ResourceType          string `json:"ResourceType"`
	Resource              string `json:"Resource"`
	VulnerabilityCategory string `json:"VulnerabilityCategory"`
	VulnerabilityValue    string `json:"VulnerabilityValue"`
}

type EngineResult struct {
	EngineType string                `json:"engineType"`
	Details    []VulnerabilityDetail `json:"details"`
}
