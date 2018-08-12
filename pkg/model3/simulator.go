package model3

import (
	"strings"
	"time"

	"github.com/Pallinder/go-randomdata"

	"fmt"
	"math/rand"

	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

// Cluster Simulator

type ClusterSim struct {
	TotalActions                    int
	NumUsers                        int
	MaxPodsPerApp                   int
	ChurnProbability                float32
	events                          []func()
	eventsProcessed                 int
	EventsPerMinute                 int
	Namespaces                      map[string]map[string]*Image
	ScanCapacityPerSimulationPeriod int
	Vulns                           []int
	RegistrySize                    int
	Registry                        *Registry
	st                              *ScanTool
}

func (c *ClusterSim) Describe() string {
	sA := fmt.Sprintf("apps: %v", len(c.Namespaces))
	uniq := map[string]bool{}
	//total vulnerabilities.
	for _, images := range c.Namespaces {
		for _, img := range images {
			if img.HasHighVulns || img.HasLowVulns || img.HasMedVulns {
				uniq[img.SHA] = true
			}
		}
	}

	description := fmt.Sprintf("apps: %v images %v time:[%v] days, vulntime:[%v] days",
		sA,                               // apps
		len(uniq),                        // images
		c.TimeSoFar().Hours()/24,         // days
		c.VulnerabilityTime().Hours()/24) // how many days vulnerable
	return description
}

// TimeElapsedPerEvent gives a simple way to estimate the 'real' time
// That has passed during a cluster simulation scenario. Note that all events
// currently take a constante, equal amount of time, so the eventID is really just
// a placeholder for a future wherein we simulate events happening in a non uniform
// timescale.
func (c *ClusterSim) TimeElapsedPerEvent(eventID int) time.Duration {
	return time.Duration(c.EventsPerMinute) * time.Minute
}

// VulnerabilityTime returns the total amount of time that you've been vulnerable.
func (c *ClusterSim) VulnerabilityTime() time.Duration {
	totalVulnTime := 0 * time.Second
	for i, v := range c.Vulns {
		if v > 0 {
			totalVulnTime = totalVulnTime + time.Duration(c.TimeElapsedPerEvent(i))
		}
	}
	totalTime := 0 * time.Second
	for i := 0; i < c.eventsProcessed; i++ {
		totalTime = totalTime + time.Duration(c.eventsProcessed)*c.TimeElapsedPerEvent(i)
	}

	logrus.Infof("vuln time: %v , total time: %v  [ %v ] ", totalVulnTime, totalTime, c.eventsProcessed)
	return totalVulnTime
}

func randApp(pods int, r *Registry) (string, map[string]*Image) {
	ns := strings.ToLower(randomdata.SillyName())
	numPods := util.RandIntFromDistribution(pods/2, pods/2)
	if numPods <= 0 {
		logrus.Warnf("Warning: had to set num pods to 1 b/c neg or zero value %v", numPods)
		numPods = 1
	}

	allpods := make(map[string]*Image)
	for i := 0; i < numPods; i++ {
		img := r.RandImageFrom()
		allpods[img.SHA] = img
	}
	return ns, allpods
}

func (c *ClusterSim) Initialize() {
	m := map[string]map[string]*Image{}
	c.Namespaces = m
	if c.TotalActions == 0 {
		logrus.Warn("Setting a default for TotalActions, not specified.")
		c.TotalActions = 1000
	}
	c.st = &ScanTool{}
	c.Vulns = []int{}

	if c.EventsPerMinute == 0 {
		panic("time period must be non-zero")
	}
	if c.ScanCapacityPerSimulationPeriod == 0 {
		logrus.Info("Setting scan capacity to 200 !")
		c.ScanCapacityPerSimulationPeriod = 200
	}

	if c.Registry == nil {
		logrus.Infof("Making new registry !")
		c.Registry = NewRegistry(c.RegistrySize, 10)
	}

	// now, populate...
	for {
		app, pods := randApp(c.MaxPodsPerApp, c.Registry) // map[int32]*Img
		c.Namespaces[app] = pods
		if len(c.Namespaces) == c.NumUsers {
			break
		}
	}
	c.events = c.initEvents()

}

func (c *ClusterSim) initEvents() []func() {
	c.events = []func(){}
	for {
		// Decide how many total events to simulate.
		deletes, adds := func() (deletes []string, adds map[string]map[string]*Image) {
			adds = map[string]map[string]*Image{}
			deletes = []string{}

			// (1) plan all the changes that happened in this time span, w/o mutating anything.
			for app, _ := range c.Namespaces {
				// churn event !
				if c.ChurnProbability > rand.Float32() {
					// 50% probability that we either add or delete something.
					if rand.Intn(10) < 5 {
						deletes = append(deletes, app)
					} else {
						newApp, newPods := randApp(c.MaxPodsPerApp, c.Registry)
						adds[newApp] = newPods
					}
				}
			}
			return deletes, adds
		}()
		// Decide how many scan events we need to simulate.
		scans := c.ScanCapacityPerSimulationPeriod

		d := 0
		a := 0
		s := 0
		// (2) now, do all the map mutation actions to an event q.
		for _, app := range deletes {
			c.events = append(c.events, func() {
				delete(c.Namespaces, app)
			})
		}
		for app, pods := range adds {
			c.events = append(c.events, func() {
				c.Namespaces[app] = pods
			})
		}
		for i := 0; i < scans; i++ {
			c.events = append(c.events, func() {
				c.st.ScanNewImage()
			})
		}

		if len(c.events)%2 == 0 {
			logrus.Infof("events created so far: %v", len(c.events))
		}

		if len(c.events) >= c.TotalActions {
			logrus.Infof("--- events created --- %v ( %v %v %v )", len(c.events), d, a, s)
			return c.events
		}
	}
}

// Increment Increments the state of the cluster by one time period.  i.e. one day.
func (c *ClusterSim) ExportSimulationCheckpointStatistics() {
	// initially the length of 'state' is # the initial users.
	deletes := []string{}
	adds := map[string]map[string]*Image{}

	// now, do all the map mutation actions....
	for _, app := range deletes {
		delete(c.Namespaces, app)
	}
	for app, pods := range adds {
		c.Namespaces[app] = pods
	}
}

func (c *ClusterSim) RunAllEvents() {
	for len(c.events) > 0 {
		e, _c := util.RandRemove(c.events)
		c.events = _c
		e()
		c.eventsProcessed++
		c.UpdateMetrics()
		c.VulnerabilityTime()
		logrus.Infof("remaining events: %v", len(c.events))
	}
	logrus.Infof("done !")
}

// UpdateMetrics updates prometheus metrics.  Note that it also updates the total vulns, which
// records the values at every time point in the simulation.  This is b/c some metrics may not be
// scraped, due to simulation velocity.
func (c *ClusterSim) UpdateMetrics() {
	// immediately invoked self executing function !
	metrics := func() {
		var h, m, l int
		// calculate steady state of vulns, emit metrics.
		for _, images := range c.Namespaces {
			for _, img := range images {
				// if unscanned... queue it.
				if _, ok := c.st.Scanned[img.SHA]; !ok {
					c.st.Enqueue(img)
					// if not scanned, increment its vulns...
					if !ok {
						if img.HasHighVulns {
							h++
						}
						if img.HasMedVulns {
							m++
						}
						if img.HasLowVulns {
							l++
						}
					}
				}
			}
		}
		if l > 0 || m > 0 || h > 0 {
			c.Vulns = append(c.Vulns, l+m+h)
		} else {
			c.Vulns = append(c.Vulns, 0)
			//logrus.Infof("%v\n", c.Vulns)
		}
	}
	metrics()
}

func (c *ClusterSim) TimeSoFar() time.Duration {
	d := 0 * time.Second
	for i := 0; i < c.eventsProcessed; i++ {
		d = d + c.TimeElapsedPerEvent(i)
	}
	logrus.Infof("time soo far %v ", d)
	return d
}

func (c *ClusterSim) Plot() ([]float64, []float64) {
	dataX := []float64{}
	dataY := []float64{}
	for i, v := range c.Vulns {
		dataX = append(dataX, float64(i))
		dataY = append(dataY, float64(v))
	}

	return dataX, dataY
}

func (c *ClusterSim) Simulate() {
	if c.Registry == nil && c.RegistrySize == 0 {
		panic("registry size, at least, must be given ... or create the registry yourself.")
	}
	c.Initialize()
	c.RunAllEvents()
	logrus.Infof(c.Describe())

	x, y := c.Plot()
	logrus.Infof("%v %v", x, y)
}
