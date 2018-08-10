package model3

import "time"

// Cluster Simulator

type ClusterSim struct {
	NumUsers                        int
	MaxPodsPerApp                   int
	ChurnProbability                float32
	Increments                      int64
	events                          []func()
	IncrementTimePeriod             time.Duration
	Namespaces                      map[string]map[string]Image
	ScanCapacityPerSimulationPeriod int
	Vulns                           []int
	RegistrySize                    int
	st                              *ScanTool
}
