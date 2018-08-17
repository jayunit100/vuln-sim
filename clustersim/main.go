package main

import (
	"fmt"
	"os"
	"time"

	// <- ui shortcut, optional

	"github.com/jayunit100/vuln-sim/pkg/model3"
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

func main() {

	//	test()
	//	return

	testUI()
	return

	c := &model3.ClusterSim{
		ChurnProbability: .10,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     1000,
		ScansPerMinute:   float32(1),
		SimTime:          time.Duration(5) * time.Hour,
	}

	c.Simulate()

	d := &model3.ClusterSim{
		ChurnProbability: .10,
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     1000,
		ScansPerMinute:   float32(5),
		SimTime:          time.Duration(5) * time.Hour,
	}

	d.Simulate()

	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")

	logrus.Infof("1 hubs..........")
	logrus.Infof("%v", c.Describe())

	logrus.Infof("****************************************************")
	logrus.Infof("****************************************************")

	logrus.Infof("10 hubs..........")
	logrus.Infof("%v", d.Describe())

}
