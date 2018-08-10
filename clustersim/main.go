package main

import (
	"time"

	"github.com/jayunit100/vuln-sim/pkg/model2"
) // <- ui shortcut, optional

func main() {
	c := model2.ClusterSim{
		ChurnProbability:                .10,
		IncrementTimePeriod:             24 * time.Hour,
		MaxPodsPerApp:                   10,
		NumUsers:                        1000,
		RegistrySize:                    10 * 1000,
		ScanCapacityPerSimulationPeriod: 20,
	}

	c.Simulate()
}
