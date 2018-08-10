package model3

type Image struct {
	SHA          string
	Name         string
	Tags         []string
	HasLowVulns  bool
	HasMedVulns  bool
	HasHighVulns bool
}
