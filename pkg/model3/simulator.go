package model3

import (
	"math"
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
	SimTime          time.Duration
	NumUsers         int
	MaxPodsPerApp    int
	ChurnProbability float32
	events           []func() string
	eventsProcessed  int
	EventsPerMinute  int // Determines Total Actions...
	Namespaces       map[string]map[string]*Image
	ScansPerMinute   float32
	ScanFailureRate  func() float32
	Vulns            []int
	VulnsHigh        []int
	RegistrySize     int
	Registry         *Registry
	st               *ScanTool
	ActionLog        []map[string]int // [ {"adds",1}.{"deletes",3}], ...}
}

// TotalActions returns the amount of total actions which will ever occur.
func (c *ClusterSim) TotalActions() int {
	//logrus.Infof("total actions: %v / %v", c.EventsPerMinute, c.SimTime.Minutes())
	return c.EventsPerMinute * int(c.SimTime.Minutes()) // ->events
}

// TotalScanActions returns the total amount of scan actions which we expect to occur over the simulation.
func (c *ClusterSim) TotalScanActions() float32 {
	return float32(float64(c.ScansPerMinute) * c.SimTime.Minutes())
}

func (c *ClusterSim) Describe() string {
	sA := fmt.Sprintf("%v", len(c.Namespaces))

	uniqImages := map[string]bool{}

	uniqImagesWVulns := map[string]bool{}
	//total vulnerabilities.
	for _, images := range c.Namespaces {
		for _, img := range images {
			if img.HasHighVulns || img.HasLowVulns || img.HasMedVulns {
				uniqImagesWVulns[img.SHA] = true
			} else {
				uniqImages[img.SHA] = true
			}
		}
	}

	// longest safe run...
	longest := 0.0
	func() {
		curr := 0.0
		for _, v := range c.Vulns {
			if v == 0 {
				curr++
			} else {
				curr = 0
			}
			longest = math.Max(longest, curr)
		}
	}()

	description := fmt.Sprintf("FINAL STATE: scanrate %v, \nScans done %v , \nReg size... %v \nApps... %v\nFinal vuln images that are running..... %v \nUnique images with vulnerabilities............ %v\nTime.......%.5f days \n*** Vuln time **** ....... %.2f days.\nLongest run of events when safe: %v (out of %v)",
		c.TotalScanActions(),
		len(c.st.Scanned),
		c.RegistrySize,
		sA,              // apps
		len(uniqImages), // images
		len(uniqImagesWVulns),
		c.TimeSoFar().Hours()/24, // days
		c.VulnerabilityTime().Hours()/24,
		longest,
		c.eventsProcessed,
	)

	return description
}

// TimeElapsedPerEvent gives a simple way to estimate the 'real' time
// That has passed during a cluster simulation scenario. Note that all events
// currently take a constante, equal amount of time, so the eventID is really just
// a placeholder for a future wherein we simulate events happening in a non uniform
// timescale.
func (c *ClusterSim) TimeElapsedPerEvent(eventID int) time.Duration {
	// 10 events per minute / 1 minute  =
	return time.Minute / time.Duration(c.EventsPerMinute)
}

// VulnerabilityTime returns the total amount of time that you've been vulnerable.
func (c *ClusterSim) VulnerabilityTime() time.Duration {
	totalVulnTime := 0 * time.Second
	for i, v := range c.Vulns {
		if v > 0 {
			totalVulnTime = totalVulnTime + c.TimeElapsedPerEvent(i)
		}
	}

	// logrus.Infof("vuln time: %v , total time: %v  [ %v ] ", totalVulnTime, c.TimeSoFar(), c.eventsProcessed)
	return totalVulnTime
}

var tooLow int

func randApp(pods int, r *Registry) (string, map[string]*Image) {
	ns := strings.ToLower(randomdata.SillyName())
	numPods := util.RandIntFromDistribution(pods/2, pods/2)
	if numPods <= 0 {
		//logrus.Warnf("Warning: had to set num pods to 1 b/c neg or zero value %v", numPods)
		tooLow++
		numPods = 1
	}
	//util.RandLog(2, fmt.Sprintf("num pods had to get set to 1, was 0 %v", tooLow))

	allpods := make(map[string]*Image)
	for i := 0; i < numPods; i++ {
		img := r.RandImageFrom()
		allpods[img.SHA] = img
	}
	return ns, allpods
}

func (c *ClusterSim) Initialize() {
	m := map[string]map[string]*Image{}

	// This is a knob that simulates a 'scan' tool which degrades performance over time.
	if c.ScanFailureRate == nil {
		logrus.Infof("ChurnProbabiltiyFunction is nil, setting a default to return the constant.")
		c.ScanFailureRate = func() float32 {
			return 0
		}
	}

	c.Namespaces = m
	if c.SimTime == 0*time.Second {
		panic("Need a sim time of non zero: How long do you want to simulate events for???")
	}
	c.st = &ScanTool{}
	c.Vulns = []int{}

	if c.EventsPerMinute == 0 {
		panic("time period must be non-zero")
	}
	if c.ScansPerMinute == 0 {
		panic("No scans? Surely you are running this to simulate a cluster that is doing something to remediate vulns! Set ScansPerMinute=.5 or something.")
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

func (c *ClusterSim) initEvents() []func() string {
	c.events = []func() string{}
	d := 0
	a := 0
	for {
		// Decide how many total events to simulate.
		deletes, adds := func() (deletes []string, adds map[string]map[string]*Image) {
			adds = map[string]map[string]*Image{}
			deletes = []string{}

			// every namespace will lead to either
			// 		1 - its own deletion
			//		2 - the creation of a new namespace
			// over time, the probability of adding/deleting is thus equal, resulting
			// in dynamic equilibrium
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

		// (2) now, do all the map mutation actions to an event q.
		for _, app := range deletes {
			d++
			c.events = append(c.events, func() string {
				//		logrus.Infof("event:delete")
				delete(c.Namespaces, app)
				for _, img := range c.Namespaces[app] {
					c.st.DeprioritizeBy1(img)
				}
				return "delete"
			})
		}
		for app, pods := range adds {
			a++
			c.events = append(c.events, func() string {
				//		logrus.Infof("event:add")
				c.Namespaces[app] = pods
				return "add"
			})
		}

		if len(c.events)%100 == 0 {
			logrus.Infof("events created so far: %v ... (del %v, add %v)", len(c.events), d, a)
		}
		if len(c.events) >= c.TotalActions() {
			break
		}
	}
	// for performance, otherwise, append calls over time of simulation, can take minutes.
	c.Vulns = make([]int, len(c.events)+1)
	return c.events
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
func (c *ClusterSim) AvgScansPerEvent() float32 {
	scanProbability := float32(c.TotalScanActions()) / float32(c.TotalActions())
	return scanProbability
}

var scans float32

func (c *ClusterSim) RunAllEvents() {
	for len(c.events) > 0 {
		e, _c := util.RandRemove(c.events)
		c.events = _c

		runScans := func() {
			// make incremental progress, i.e. 1/2 a scan, 1/3 a scan, ... every time point.
			scans += util.RandFloatFromDistribution(float32(c.AvgScansPerEvent()), float32(c.AvgScansPerEvent()))
			logrus.Infof("%v scans suggested, assuming no failure stochastic", scans)
			// once you hit an integer value, complete a scan.
			if int(scans) > len(c.st.Scanned) {
				c.st.ScanNewImage()
			}
		}
		runScans()
		e()
		c.eventsProcessed++
		c.UpdateMetrics()
		c.VulnerabilityTime()
	}
	logrus.Infof("scans: %v", scans)
}

// UpdateMetrics updates prometheus metrics.  Note that it also updates the total vulns, which
// records the values at every time point in the simulation.  This is b/c some metrics may not be
// scraped, due to simulation velocity.

func (c *ClusterSim) UpdateMetrics() {
	eventId := c.eventsProcessed
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
			c.Vulns[eventId] = l + m + h
		} else {
			c.Vulns[eventId] = 0
		}
		/**
		if h > 0 {
			c.VulnsHigh = append(c.VulnsHigh, h)
		} else {
			c.VulnsHigh = append(c.VulnsHigh, 0)
		}
		**/
	}
	metrics()
}

func (c *ClusterSim) TimeSoFar() time.Duration {
	d := 0 * time.Second
	for i := 0; i < c.eventsProcessed; i++ {
		d = d + c.TimeElapsedPerEvent(i)
	}
	//	logrus.Infof("time soo far %v (events = %v)", d, c.eventsProcessed)
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

func (c *ClusterSim) Simulate() bool {
	if c.Registry == nil && c.RegistrySize == 0 {
		panic("registry size, at least, must be given ... or create the registry yourself.")
	}
	c.Initialize()
	c.RunAllEvents()
	logrus.Infof(c.Describe())

	return true
	// x, y := c.Plot()
	// logrus.Infof("%v %v", x, y)
}
