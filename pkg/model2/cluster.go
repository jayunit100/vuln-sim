package model2

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	chart "github.com/wcharczuk/go-chart"

	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

type ClusterSim struct {
	NumUsers         int
	MaxPodsPerApp    int
	ChurnProbability float32

	// dont need to set these at startup, their handled via initialization.
	Increments                      int64
	events                          []func()
	TimePeriod                      time.Duration
	StateApp                        map[string]map[int32]*Img
	ScanCapacityPerSimulationPeriod int
	Vulns                           []int
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

// VulnerabilityTime returns the total amount of time that you've been vulnerable.
func (c *ClusterSim) VulnerabilityTime() time.Duration {
	totalVulnTime := 0 * time.Second
	for _, v := range c.Vulns {
		if v > 0 {
			totalVulnTime = totalVulnTime + c.TimePeriod
		}
	}
	totalTime := time.Duration(c.Increments) * c.TimePeriod
	logrus.Infof("vuln time: %v , total time: %v", totalVulnTime, totalTime)
	return totalVulnTime
}

func (c *ClusterSim) Initialize() {
	m := map[string]map[int32]*Img{}
	c.StateApp = m
	c.Increments = 0
	c.Vulns = []int{}

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
			break
		}
	}
	c.events = c.initEvents(1000)

}

func (c *ClusterSim) initEvents(totalActions int) []func() {
	c.events = []func(){}
	for {
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

		// (2) now, do all the map mutation actions to an event q.
		for _, app := range deletes {
			Generic.WithLabelValues("Deletes").Inc()
			c.events = append(c.events, func() {
				delete(c.StateApp, app)
			})
		}
		for app, pods := range adds {
			Generic.WithLabelValues("AddPod").Inc()
			c.events = append(c.events, func() {
				c.StateApp[app] = pods
			})
		}
		for i := 0; i < scans; i++ {
			c.events = append(c.events, func() {
				st.ScanNewImage()
			})
		}

		if len(c.events)%100 == 0 {
			logrus.Infof("events created so far: %v", len(c.events))
		}

		if len(c.events) >= totalActions {
			return c.events
		}
	}
}

// Increment Increments the state of the cluster by one time period.  i.e. one day.
func (c *ClusterSim) ExportSimulationCheckpointStatistics() {
	Generic.WithLabelValues("TotalApps").Set(float64(len(c.StateApp)))
	// initially the length of 'state' is # the initial users.
	deletes := []string{}
	adds := map[string]map[int32]*Img{}

	// now, do all the map mutation actions....
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

func (c *ClusterSim) RunAllEvents() {

	highVulns := make(chan prometheus.Metric)
	go func() {
		for {
			v := <-highVulns
			logrus.Infof("change to vulns %v", v.Desc().String)
		}
	}()

	for len(c.events) > 0 {
		c.Increments++
		if c.Increments < 0 {
			panic("increment overflow ")
		}
		e, _c := util.RandRemove(c.events)
		c.events = _c
		e()
		c.UpdateMetrics()
		c.VulnerabilityTime()
	}
}

var st = &ScanTool{}

// UpdateMetrics updates prometheus metrics.  Note that it also updates the total vulns, which
// records the values at every time point in the simulation.  This is b/c some metrics may not be
// scraped, due to simulation velocity.
func (c *ClusterSim) UpdateMetrics() {
	VulnsMetric.Reset() // todo... is this necessary?
	// immediately invoked self executing function !
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
		VulnsMetric.WithLabelValues(fmt.Sprintf("High")).Set(float64(h))
		VulnsMetric.WithLabelValues(fmt.Sprintf("Med")).Set(float64(m))
		VulnsMetric.WithLabelValues(fmt.Sprintf("Low")).Set(float64(l))
		if l > 0 || m > 0 || h > 0 {
			c.Vulns = append(c.Vulns, l+m+h)
		} else {
			c.Vulns = append(c.Vulns, 0)
			logrus.Infof("%v\n", c.Vulns)
		}
	}
	metrics()
}

func (c *ClusterSim) TimeSoFar() time.Duration {
	d := c.TimePeriod * time.Duration(c.Increments)
	logrus.Infof("time soo far %v ", d)
	return d
}

func (c *ClusterSim) Plot() (*bytes.Buffer, []float64, []float64) {
	dataX := []float64{}
	dataY := []float64{}
	for i, v := range c.Vulns {
		dataX = append(dataX, float64(i))
		dataY = append(dataY, float64(v))
	}
	graph := chart.Chart{
		Series: []chart.Series{
			chart.ContinuousSeries{
				XValues: dataX,
				YValues: dataY,
			},
		},
	}
	buffer := bytes.NewBuffer([]byte{})
	err := graph.Render(chart.PNG, buffer)
	if err != nil {
		panic(err)
	}
	return buffer, dataX, dataY
}

func Simulate(c *ClusterSim) {
	c.Initialize()
	c.RunAllEvents()
	logrus.Infof(".. simulated time periods \ndesc:[%v] \ntime:[%v] days,\nvulntime:[%v] days",
		c.Describe(),
		c.TimeSoFar().Hours()/24,
		c.VulnerabilityTime().Hours()/24)

	_, x, y := c.Plot()
	logrus.Infof("%v %v", x, y)
}
