package model2

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

type ClusterSim struct {
	NumUsers         int
	MaxPodsPerApp    int
	ChurnProbability float32
	// dont need to set these at startup, their handled via initialization.
	Increments                      int
	TimePeriod                      time.Duration
	StateApp                        map[string]map[int32]*Img
	ScanCapacityPerSimulationPeriod int
}

func (c *ClusterSim) Describe() string {
	sA := fmt.Sprintf("apps: %v", len(c.StateApp))
	i := 0
	uniq := map[int32]bool{}
	//total vulnerabilities.
	for _, sha_img := range c.StateApp {
		i += len(sha_img)
		for k, _ := range sha_img {
			uniq[k] = true
		}
	}

	return fmt.Sprintf("\t %v\n\tcontainers: %v\n\timages %v", sA, i, len(uniq))
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
	c.Increments = 0
	if c.TimePeriod == 0 {
		panic("time period must be non-zero")
	}
	if c.ScanCapacityPerSimulationPeriod == 0 {
		logrus.Info("Setting scan capacity to 200 !")
		c.ScanCapacityPerSimulationPeriod = 200
	}

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

// Increment Increments the state of the cluster by one time period.  i.e. one day.
func (c *ClusterSim) ExportSimulationCheckpointStatistics() {
	c.Increments++
	Generic.WithLabelValues("TotalApps").Set(float64(len(c.StateApp)))
	// initially the length of 'state' is # the initial users.
	deletes := []string{}
	adds := map[string]map[int32]*Img{}

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

func (c *ClusterSim) Simulate() {
	// Decide how many total events to simulate.
	deletes, adds := func() (deletes []string, adds map[string]map[int32]*Img) {
		adds = map[string]map[int32]*Img{}
		deletes = []string{}

		// (1) plan all the changes that happened in this time span, w/o mutating anything.
		for app, _ := range c.StateApp {
			// churn event !
			if c.ChurnProbability > rand.Float32() {
				// 50% probability that we either add or delete something.
				if rand.Intn(10) < 5 {
					deletes = append(deletes, app)
				} else {
					newApp, newPods := randApp(c.MaxPodsPerApp)
					adds[newApp] = newPods
				}
			}
		}
		return deletes, adds
	}()

	// Decide how many scan events we need to simulate.
	scans := c.ScanCapacityPerSimulationPeriod

	events := []func(){}
	// (2) now, do all the map mutation actions to an event q.
	for _, app := range deletes {
		Generic.WithLabelValues("Deletes").Inc()
		events = append(events, func() {
			delete(c.StateApp, app)
		})
	}
	for app, pods := range adds {
		Generic.WithLabelValues("AddPod").Inc()
		events = append(events, func() {
			c.StateApp[app] = pods
		})
	}
	for i := 0; i < scans; i++ {
		events = append(events, func() {
			st.ScanNewImage()
		})
	}

	// (3) now execute them one at a time, after shuffling them.
	for len(events) > 0 {
		e, eventss := util.RandRemove(events)
		events = eventss // no idea why i cant do the assignment above.
		e()
	}
}

var st = &ScanTool{}

// UpdateMetrics
func (c *ClusterSim) UpdateMetrics() {
	Vulns.Reset()

	metrics := func() {
		var h, m, l int

		// calculate steady state of vulns, emit metrics.
		for _, images := range c.StateApp {
			for _, img := range images {
				// if unscanned... queue it.
				if _, ok := st.Scanned[img.K]; !ok {
					st.Enqueue(img)
					// if not scanned, increment its vulns...
					if !ok {
						if img.H {
							h++
						}
						if img.M {
							m++
						}
						if img.L {
							l++
						}
					}
				}
			}
		}
		Vulns.WithLabelValues(fmt.Sprintf("High")).Set(float64(h))
		Vulns.WithLabelValues(fmt.Sprintf("Med")).Set(float64(m))
		Vulns.WithLabelValues(fmt.Sprintf("Low")).Set(float64(l))

		if l > 0 || m > 0 || h > 0 {
			logrus.Infof("Vulns found...")
		}
	}
	metrics()
}

func (c *ClusterSim) TimeSoFar() time.Duration {
	logrus.Infof("period:%v incr:%v", c.TimePeriod, c.Increments)
	seconds := float64(c.Increments) * (c.TimePeriod.Seconds())
	return time.Duration(seconds) * time.Second
}

func Simulate(c *ClusterSim) {
	c.Initialize()
	total := 0
	for {
		logrus.Infof("...  %v", total)
		for i := 0; i < 100; i++ {
			c.Simulate()
			c.UpdateMetrics()
			logrus.Infof(".. simulated time periods %v .. \n description: %v ... total time : %v days", i, c.Describe(), c.TimeSoFar().Hours()/24)
			total++
			time.Sleep(1 * time.Second)
		}
		if total > 365 {
			logrus.Info("........ done .........")
			return
		}
	}
}
