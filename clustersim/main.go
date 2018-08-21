package main

import (
	"fmt"
	"os"
	"time"

	// <- ui shortcut, optional

	"github.com/jayunit100/vuln-sim/pkg/model3"
	"github.com/jayunit100/vuln-sim/pkg/view"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
)

// <- ui shortcut, optional
func test() {
	data := [][]string{}

	regMax := 5000
	scanMax := 100

	header := func() []string {
		h := []string{}
		i := 0
		h = append(h, "--------")

		for ScansPerMinute := 1; ScansPerMinute < scanMax; ScansPerMinute += 20 {
			i++
			h = append(h, fmt.Sprintf("S/M:%v", ScansPerMinute))
		}
		return h
	}()

	for regSize := 1000; regSize < regMax; regSize += 1000 {
		registries := []string{fmt.Sprintf("regsize:%v", regSize)}
		for ScansPerMinute := 1; ScansPerMinute < scanMax; ScansPerMinute += 20 {
			c := &model3.ClusterSim{
				ChurnProbability: .10,
				EventsPerMinute:  10,
				MaxPodsPerApp:    10,
				NumUsers:         100,
				RegistrySize:     regSize,
				ScansPerMinute:   float32(ScansPerMinute),
				SimTime:          time.Duration(5) * time.Hour,
			}
			c.Simulate()
			registries = append(registries, fmt.Sprintf("%v", c.VulnerabilityTime()))
		}
		data = append(data, registries)
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.Append(header)
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}

func experiment1() {
	c := &model3.ClusterSim{
		ChurnProbability: .10,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     1000,
		ScansPerMinute:   float32(1000),
		SimTime:          time.Duration(48) * time.Hour,
	}
	c.Simulate()
	d := &model3.ClusterSim{
		ChurnProbability: .10,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     1000,
		ScansPerMinute:   float32(2000),
		SimTime:          time.Duration(48) * time.Hour,
	}
	d.Simulate()
	logrus.Infof("%v", c.Describe())
	logrus.Infof("%v", d.Describe())
	view.LaunchUI(map[string]*model3.ClusterSim{
		"sim1:": c,
		"sim2:": d,
	})
}

func ExperimentalSimulation1() {
	base := &model3.ClusterSim{
		ChurnProbability: .05,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     10000,
		ScansPerMinute:   float32(2), // this is really fast !
		SimTime:          time.Duration(48) * time.Hour,
	}

	done := make(chan bool)

	// simulation #1: baseline.
	b := *base
	go func() {
		done <- b.Simulate()
	}()

	c := *base

	// simulation #2
	stormOccured := false
	go func() {
		c.ScanFailureRate = func() float32 {
			if !stormOccured && c.TimeSoFar().Hours() > 5 {
				stormOccured = true
				return .5
			} else {
				return 0
			}
		}
		done <- c.Simulate()
	}()

	<-done
	<-done

	view.LaunchUI(map[string]*model3.ClusterSim{
		"2xScanRate:": &b,
		"2xUsers:":    &c,
	})
}

func main() {
	defer profile.Start().Stop()

	ExperimentalSimulation1()
}
