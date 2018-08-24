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

type NsVulnMap map[string]map[string]*Image
type ClusterSim struct {
	SimTime                                time.Duration
	NumUsers                               int
	MaxPodsPerApp                          int
	ChurnProbability                       float32
	events                                 []func() string
	eventsProcessed                        int
	EventsPerMinute                        int // Determines Total Actions...
	Namespaces                             map[string]map[string]*Image
	ScansPerMinute                         float32
	ScanFailureRate                        func() float32
	CurrentVulns                           NsVulnMap
	IntroducedVulnsAsMapOfNSAtTimeToImages map[int]NsVulnMap
	scans                                  float32
	/**
	{
		104810:{"myns1":{"high":2,"med":3,"low":10},
			   {"myns2":{"high":2,"med":3,"low":10}
	**/
	RegistrySize          int
	Registry              *Registry
	st                    *ScanTool
	ActionLog             []map[string]int // [ {"adds",1}.{"deletes",3}], ...}
	SimulationRunComplete bool
	History               *History
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

// TODO finish cleaning this function up !!!!!!!!!!
func (c *ClusterSim) CalcVulnsAt(vulnMap []*Image, time int) int {
	val := 0
	for _, img := range vulnMap {
		scanned := true
		// something was scanned iff , it was scanned + it was scanned before time X.
		if lookupTime, ok := c.st.History[img.SHA]; ok {
			if lookupTime > time {
				scanned = false
			}
		}

		if !scanned && (img.HasHighVulns || img.HasMedVulns || img.HasLowVulns) {
			val++
		} else {
			logrus.Infof("Was scanned already %v (total scans : %v/%v queue ", img.SHA, len(c.st.Scanned), len(c.st.Queue))
		}
	}
	return val
}

func (c *ClusterSim) Vulns() []int {
	panic("reimplement me")
}

func (c *ClusterSim) Describe() string {
	if !c.SimulationRunComplete {
		panic("Cant describe before simulation ran !")
	}
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
		for _, v := range c.Vulns() {
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
	for i, v := range c.Vulns() {
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
	allpods := make(map[string]*Image)
	for i := 0; i < numPods; i++ {
		img := r.RandImageFrom()
		allpods[img.SHA] = img
	}
	return ns, allpods
}

func (c *ClusterSim) Initialize() {
	c.IntroducedVulnsAsMapOfNSAtTimeToImages = make(map[int]NsVulnMap)
	c.CurrentVulns = make(NsVulnMap)
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

	if c.EventsPerMinute == 0 {
		panic("time period must be non-zero")
	}
	if c.ScansPerMinute == 0 {
		panic("No scans? Surely you are running this to simulate a cluster that is doing something to remediate vulns! Set ScansPerMinute=.5 or something.")
	}

	if c.Registry == nil {
		logrus.Infof("Making new registry !")
		c.Registry = NewRegistry(c.RegistrySize, c.RegistrySize)
	}

	c.History = &History{}
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
			c.events = append(c.events,
				// ****************************
				// SIMULATE: DELETING AN EXISTING NAMESPACE
				func() string {
					delete(c.Namespaces, app)
					imageList := []*Image{}
					for _, img := range c.Namespaces[app] {
						c.st.DeprioritizeBy1(img)
						imageList = append(imageList, img)
					}
					c.History.ApplyDestroy(app, imageList)
					return "delete"
				})
		}
		for app, pods := range adds {
			a++
			c.events = append(c.events,
				// *****************************
				// SIMULATE: CREATE A NEW NAMESPACE
				func() string {
					c.Namespaces[app] = pods
					podsList := []*Image{}
					for _, p := range pods {
						podsList = append(podsList, p)
					}
					c.History.ApplyCreate(app, podsList)
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
	return c.events
}

func (c *ClusterSim) RegisterDelete(app string) {
	delete(c.CurrentVulns, app)
	delete(c.IntroducedVulnsAsMapOfNSAtTimeToImages[c.eventsProcessed], app)
}

// Register adding unknown vulnerabilities to the cluster.
func (c *ClusterSim) RegisterAdd(app string, img *Image) {
	if c.CurrentVulns[app] == nil {
		c.CurrentVulns[app] = map[string]*Image{}
	}
	c.CurrentVulns[app][img.SHA] = img

	// c.VulnsAsMap[c.eventsProcessed] MUST exist before calling this.
	if c.IntroducedVulnsAsMapOfNSAtTimeToImages[c.eventsProcessed][app] == nil {
		c.IntroducedVulnsAsMapOfNSAtTimeToImages[c.eventsProcessed][app] = map[string]*Image{}
	}
	c.IntroducedVulnsAsMapOfNSAtTimeToImages[c.eventsProcessed][app][img.SHA] = img

	// queue the scans.. simulating perceiver->perceptor notification.
	// TODO consider adding some latency here, to simulate SLA better, i.e.
	for sha, img := range c.Namespaces[app] {
		if _, ok := c.st.Queue[sha]; !ok {
			c.st.Enqueue(img)
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
func (c *ClusterSim) AvgScansPerEvent() float32 {
	scanProbability := float32(c.TotalScanActions()) / float32(c.TotalActions())
	return scanProbability
}

func (c *ClusterSim) RunAllEvents() {
	for len(c.events) > 0 {
		e, _c := util.RandRemove(c.events)
		c.events = _c

		runScans := func() {
			// make incremental progress, i.e. 1/2 a scan, 1/3 a scan, ... every time point.
			c.scans += util.RandFloatFromDistribution(float32(c.AvgScansPerEvent()), float32(c.AvgScansPerEvent()))

			// once you hit an integer value, complete a scan, (some fail, common if failure rate is high).
			if c.ScanFailureRate() < rand.Float32() {
				// every so often, the # of total scans increases by an integer value.
				// at a scan a minute, it increases typically .1 or so per event , assuming 10 events / minute.
				// when that happens, we make sure to 'scan a new image'.
				//logrus.Infof("scan queue  > 0 : %v, # scans > total scanned :  %v", len(c.st.Queue) > 0, int(c.scans) > len(c.st.Scanned))
				for len(c.st.Queue) > 0 && int(c.scans) > len(c.st.Scanned) {
					scannedImage := c.st.ScanNewImage(c.eventsProcessed)
					if scannedImage == "" {
						panic("scanned nothing!")
					} else {
						logrus.Infof("scanned image: [%v]", scannedImage)
					}
				}
			} else {
				logrus.Infof("SKIPPING SCAN! %v", c.ScanFailureRate())
			}

		}
		runScans()
		c.IntroducedVulnsAsMapOfNSAtTimeToImages[c.eventsProcessed] = NsVulnMap{}
		e()
		if rand.Intn(10000) == 1 {
			for ns, images := range c.CurrentVulns {
				for _, img := range images {
					util.RandLog(1, fmt.Sprintf("%v in namespace %v has vulns", img.SHA, ns))
				}
			}
		}

		util.RandLog(1, fmt.Sprintf("%.4f : work done / work remaining.", float32(c.eventsProcessed)/float32(len(c.events))))
		c.eventsProcessed++
	}
	logrus.Infof("Done w/ simulation: Total scans was %v.", c.scans)
	if c.st.scans == 0 {
		panic("This simulation was useless: no scans !")
	}
}

// UpdateMetrics updates prometheus metrics.  Note that it also updates the total vulns, which
// records the values at every time point in the simulation.  This is b/c some metrics may not be
// scraped, due to simulation velocity.

func (c *ClusterSim) TimeSoFar() time.Duration {
	d := 0 * time.Second
	for i := 0; i < c.eventsProcessed; i++ {
		d = d + c.TimeElapsedPerEvent(i)
	}
	return d
}

func (c *ClusterSim) Plot() ([]float64, []float64) {
	dataX := []float64{}
	dataY := []float64{}
	for i, v := range c.Vulns() {
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
	c.SimulationRunComplete = true
	return true
}
