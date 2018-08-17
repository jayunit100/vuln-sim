package main

import (
	"fmt"
	"os"
	"time"

	// <- ui shortcut, optional

	"github.com/jayunit100/vuln-sim/pkg/model3"
	"github.com/jayunit100/vuln-sim/pkg/view"
	"github.com/olekukonko/tablewriter"
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

func EXPshowEffectOfDoublingUsers() {
	base := &model3.ClusterSim{
		ChurnProbability: .10,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     1000,
		ScansPerMinute:   float32(100),
		SimTime:          time.Duration(100) * time.Hour,
	}

	b := *base
	b.ScansPerMinute = 2 * base.ScansPerMinute
	b.Simulate()

	c := *base
	c.NumUsers = 2 * base.NumUsers
	c.Simulate()

	d := *base
	d.ScansPerMinute = 2 * base.ScansPerMinute
	d.NumUsers = 2 * base.NumUsers
	d.Simulate()

	view.LaunchUI(map[string]*model3.ClusterSim{
		"baseline:":          &b,
		"2xUsers:":           &c,
		"2xUsers2xScanRate:": &d,
	})
}

func main() {
	EXPshowEffectOfDoublingUsers()
}
