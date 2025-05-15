package handler

type VulnerabilityDetail struct {
	ResourceType          string `json:"ResourceType"`
	Resource              string `json:"Resource"`
	VulnerabilityCategory string `json:"VulnerabilityCategory"`
	VulnerabilityValue    string `json:"VulnerabilityValue"`
}

type EngineResult struct {
	PluginType string                `json:"plugin"`
	EngineType string                `json:"engineType"`
	Details    []VulnerabilityDetail `json:"details"`
}
