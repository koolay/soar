package run

type Output struct {
	ID             string      `json:"ID"`
	Fingerprint    string      `json:"Fingerprint"`
	Score          int         `json:"Score"`
	Sample         string      `json:"Sample"`
	Explain        interface{} `json:"Explain"`
	HeuristicRules []struct {
		Item     string `json:"Item"`
		Severity string `json:"Severity"`
		Summary  string `json:"Summary"`
		Content  string `json:"Content"`
		Case     string `json:"Case"`
		Position int    `json:"Position"`
	} `json:"HeuristicRules"`
	IndexRules interface{} `json:"IndexRules"`
	Tables     []string    `json:"Tables"`
}
