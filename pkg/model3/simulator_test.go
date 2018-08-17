package model3

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestCompareSmallAndLargeSimulations(t *testing.T) {
	// Just codifies some heurstics, for example:
	// 	- both simulations should be equal at the end.
	//	- the smaller simulation should have less vulnerabilities at the beggining.
	//	- add more later, this test is again, only for codifying that 'trends' which
	//	  approximate the real world actually occur.

	regSize := 1000 // higher reg size: longer convergence factor.
	c := Assert(.5, 10, regSize, 10, 10)
	_, smallUsersVulns := c.Plot()
	logrus.Infof("%v", c.VulnerabilityTime())

	d := Assert(.5, 100, regSize, 100, 10)
	_, bigUsersVulns := d.Plot()
	logrus.Infof("%v vs %v", c.VulnerabilityTime(), d.VulnerabilityTime())
	logrus.Infof("%v %v", len(smallUsersVulns), len(bigUsersVulns))

	// simulationLen: The exact # of events isnt the same, truncate the last few from the longer simulation...
	// difference of last 2 or 3 events is negligible...
	simulationLen := len(bigUsersVulns)
	if len(smallUsersVulns) < len(bigUsersVulns) {
		simulationLen = len(smallUsersVulns)
	}

	// debug the deltas.
	// the differences are printed out, showing the delta of # of vulnerable in cluster images.
	func() {
		lastVulnB := 0.0
		lastVulnS := 0.0
		for ii, _ := range smallUsersVulns {
			if ii >= simulationLen {
				continue
			}
			if ii%10 == 0 {
				logrus.Infof("%v: %v %v diff=(%v %v)", ii, smallUsersVulns[ii], bigUsersVulns[ii], lastVulnS-smallUsersVulns[ii], lastVulnB-bigUsersVulns[ii])
				lastVulnB = bigUsersVulns[ii]
				lastVulnS = smallUsersVulns[ii]
			}
		}
	}()

	func() {
		maxZerosB := 0.0
		zerosB := 0.0

		maxZerosS := 0.0
		zerosS := 0.0

		for ii, _ := range smallUsersVulns {
			if ii >= simulationLen {
				continue
			}
			if smallUsersVulns[ii] == 0 {
				zerosS++
			} else {
				zerosS = 0
			}
			if bigUsersVulns[ii] == 0 {
				zerosB++
			} else {
				zerosB = 0
			}

			// in case the string we're on is longer then the longest so far, we update our max length.
			maxZerosS = math.Max(zerosS, maxZerosS)
			maxZerosB = math.Max(zerosB, maxZerosB)
		}

		logrus.Infof("Longest run for small user set: %v", maxZerosS)
		logrus.Infof("Longest run for large user set: %v", maxZerosB)
	}()

	if !(smallUsersVulns[0] < bigUsersVulns[0]) {
		logrus.Infof("Failing ! Early on in the simulation: we expected small ( %v ) <  large ( %v ) ", smallUsersVulns[0], bigUsersVulns[0])
		t.Fail()
		return
	}

	logrus.Infof("[[[[[[ %v", len(smallUsersVulns))
	logrus.Infof("[[[[[[ %v", len(bigUsersVulns))

	if !(smallUsersVulns[2600] == bigUsersVulns[2600]) {
		logrus.Infof("Failing ! Later on in the simulation: we expected small ( %v ) == large ( %v )", smallUsersVulns[300], bigUsersVulns[300])
		t.Fail()
		return
	}

	logrus.Infof("***************** *******************")
	logrus.Infof("***************** *******************")
	logrus.Infof(c.Describe())
	logrus.Infof("***************** *******************")
	logrus.Infof(d.Describe())
	logrus.Infof("***************** *******************")
	logrus.Infof("***************** *******************")
}

// TODO FINISH PRINTING 2D HEATMAP MATRIX OF
// Registry Size vs Scans Per Minute.
func TestSimTest(t *testing.T) {
	data := [][]string{}
	regMax := 101
	scanMax := 2
	for regSize := 100; regSize < regMax; regSize += 200 {
		registries := []string{}
		for ScansPerMinute := 1; scanMax < 2; ScansPerMinute += 10 {
			c := &ClusterSim{
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
	/**
	table := tablewriter.NewWriter(os.Stdout)
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
	**/
}

func Assert(churnProb float32, numUsers int, regSize int, scanSpeedPerSim int, MaxPodsPerApp int) *ClusterSim {
	c := &ClusterSim{
		ChurnProbability: churnProb,
		EventsPerMinute:  10,
		MaxPodsPerApp:    MaxPodsPerApp,
		NumUsers:         numUsers,
		RegistrySize:     regSize,
		ScansPerMinute:   float32(1),
		SimTime:          time.Duration(5) * time.Hour,
	}

	ta := 5 * 60 * 10

	// this verifies that total actions returns the corrent # of actions , even before the sim occured. i.e. that its stateless.
	if c.TotalActions() < ta-10 {
		logrus.Warnf("total actions is way too low: %v , expected %v ", c.TotalActions(), ta)
		panic("exiting because total actions was way off, see logs above...")
	}
	c.Simulate()

	return c
}
