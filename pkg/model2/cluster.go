package model2

import (
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
)

type ClusterSim struct {
	NumUsers         int
	MaxPodsPerApp    int
	ChurnProbability float32
	// dont need to set these at startup, their handled via initialization.
	Day      int
	StateApp map[string]map[int32]*Img
}

// sync compares the amount of vulns you already
func (c *ClusterSim) sync(s map[string]bool) (knownVulnsNs int, unKnownVulns int) {
	for app, containers := range c.StateApp {
		for _, pod := range containers {
			if pod.L || pod.M || pod.H {
				if v, ok := s[app]; ok && v {
					knownVulnsNs++
				} else {
					unKnownVulns++
				}
			}
		}
	}
	return knownVulnsNs, unKnownVulns
}

func (c *ClusterSim) Initialize() {
	m := map[string]map[int32]*Img{}
	c.StateApp = m
	c.Day = 0

	// now, populate...
	for {
		Generic.WithLabelValues("NewAppInit").Inc()
		app, pods := randApp(c.MaxPodsPerApp) // map[int32]*Img
		c.StateApp[app] = pods
		if len(c.StateApp) == c.NumUsers {
			return
		}
	}
}

// Inc Increments the state of the cluster by one day.
func (c *ClusterSim) IncrementDay() {
	Generic.WithLabelValues("TotalApps").Set(float64(len(c.StateApp)))
	// initially the length of 'state' is # the initial users.
	deletes := []string{}
	adds := map[string]map[int32]*Img{}

	// (1) plan all the changes that happened in this time span, w/o mutating anything.
	for app, _ := range c.StateApp {
		// churn event !
		if c.ChurnProbability > rand.Float32() {
			Generic.WithLabelValues("ContainerChurn").Inc()
			// either add or delete something.
			if rand.Intn(3) < 1 {
				deletes = append(deletes, app)
			} else {
				newApp, newPods := randApp(c.MaxPodsPerApp)
				adds[newApp] = newPods
			}
		}
	}
	// (2) now, do all the map mutation actions...
	for _, app := range deletes {
		Generic.WithLabelValues("Deletes").Inc()
		delete(c.StateApp, app)
	}
	for app, pods := range adds {
		Generic.WithLabelValues("AddPod").Inc()
		c.StateApp[app] = pods
	}
	Generic.WithLabelValues("Days").Inc()
}

func (c *ClusterSim) Process() {
	for _, images := range c.StateApp {
		for _, img := range images {
			if img.H {
				Vulns.WithLabelValues("High").Inc()
			}
			if img.M {
				Vulns.WithLabelValues("Med").Inc()
			}
			if img.L {
				Vulns.WithLabelValues("Low").Inc()
			}
		}
	}
}

func Simulate(c *ClusterSim) {
	c.Initialize()
	total := 0
	for {
		logrus.Infof("...  %v", total)

		for i := 0; i < 100; i++ {
			c.IncrementDay()
			c.Process()
			logrus.Infof(".. incremented day %v ..", i)
			total++
			time.Sleep(2 * time.Second)
		}
		if total > 365 {
			logrus.Info("........ done .........")
			return

		}
	}
}
