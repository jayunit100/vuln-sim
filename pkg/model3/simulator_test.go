package model3

import (
	"math"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestCompareSmallAndLargeSimulations(t *testing.T) {
	// Just codifies some heurstics, for example:
	// 	- both simulations should be equal at the end.
	//	- the smaller simulation should have less vulnerabilities at the beggining.
	//	- add more later, this test is again, only for codifying that 'trends' which
	//	  approximate the real world actually occur.
	c := Assert(.5, 10, 100, 10, 10)
	_, smallUsersVulns := c.Plot()
	logrus.Infof("%v", c.VulnerabilityTime())

	d := Assert(.5, 100, 100, 100, 10)
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
			logrus.Infof("%v: %v %v diff=(%v %v)", ii, smallUsersVulns[ii], bigUsersVulns[ii], lastVulnS-smallUsersVulns[ii], lastVulnB-bigUsersVulns[ii])

			lastVulnB = bigUsersVulns[ii]
			lastVulnS = smallUsersVulns[ii]
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

	if !(smallUsersVulns[300] == bigUsersVulns[300]) {
		logrus.Infof("Failing ! Later on in the simulation: we expected small ( %v ) == large ( %v )", smallUsersVulns[300], bigUsersVulns[300])
		t.Fail()
		return
	}

}

func Assert(churnProb float32, numUsers int, regSize int, scanSpeedPerSim int, MaxPodsPerApp int) *ClusterSim {
	c := &ClusterSim{
		ChurnProbability:                churnProb,
		EventsPerMinute:                 10,
		MaxPodsPerApp:                   MaxPodsPerApp,
		NumUsers:                        numUsers,
		RegistrySize:                    regSize,
		ScanCapacityPerSimulationPeriod: scanSpeedPerSim,
		TotalActions:                    300,
	}
	c.Simulate()

	return c
}
