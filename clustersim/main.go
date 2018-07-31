package main

import (
	"github.com/jayunit100/vuln-sim/pkg/model2"
) // <- ui shortcut, optional

func main() {
	c := &model2.ClusterSim{
		ChurnProbability: .10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
	}
	model2.Simulate(c)
}
