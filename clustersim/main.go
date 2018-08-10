package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jayunit100/vuln-sim/pkg/model2"
	"github.com/sirupsen/logrus"
	chart "github.com/wcharczuk/go-chart"
) // <- ui shortcut, optional

type PlotServ struct {
	X []float64
	Y []float64
}

func (p *PlotServ) Port() string {
	if len(os.Getenv("PORT")) > 0 {
		return os.Getenv("PORT")
	}
	return "8080"
}

func (p *PlotServ) drawChart(res http.ResponseWriter, req *http.Request) {
	logrus.Infof("making chart")
	sbc := chart.BarChart{
		Title:      ".....",
		TitleStyle: chart.StyleShow(),
		Background: chart.Style{
			Padding: chart.Box{
				Top: 40,
			},
		},
		Height:   512,
		BarWidth: 60,
		XAxis: chart.Style{
			Show: true,
		},
		YAxis: chart.YAxis{
			Style: chart.Style{
				Show: true,
			},
		},
		Bars: []chart.Value{},
	}
	logrus.Infof("making chart 2")

	for i, _ := range p.X {
		if i%100 == 0 {
			sbc.Bars = append(sbc.Bars, chart.Value{
				Label: fmt.Sprintf("%v (%v)", p.X[i], p.Y[i]),
				Value: p.Y[i],
			})
		}
	}
	logrus.Infof("making chart 3")

	res.Header().Set("Content-Type", "image/png")
	logrus.Infof("making chart 4: render")

	err := sbc.Render(chart.PNG, res)
	logrus.Infof("making chart done w/ render")

	if err != nil {
		fmt.Printf("Error rendering chart: %v\n", err)
	}
}

func (p *PlotServ) Run(res http.ResponseWriter, req *http.Request) {
	// http://localhost:8080/sim?ChurnProb=.1&MaxPodsPerApp=10&NumUsers=100&RegistrySize=1000
	churnProb := req.URL.Query().Get("ChurnProb")
	maxPodsPerApp := req.URL.Query().Get("MaxPodsPerApp")
	numUsers := req.URL.Query().Get("NumUsers")
	registrySize := req.URL.Query().Get("RegistrySize")
	churnProbF, err := strconv.ParseFloat(churnProb, 32)

	logrus.Infof("%v %v %v %v", churnProb, maxPodsPerApp, numUsers, registrySize)
	if err != nil {
		panic("input")
	}
	maxPodsPerAppF, err := strconv.ParseInt(maxPodsPerApp, 10, 32)
	if err != nil {
		panic("input")
	}
	numUsersF, err := strconv.ParseInt(numUsers, 10, 32)
	if err != nil {
		panic("input")
	}
	registrySizeF, err := strconv.ParseInt(registrySize, 10, 32)
	if err != nil {
		panic("input")
	}

	c := &model2.ClusterSim{
		ChurnProbability:    float32(churnProbF),
		MaxPodsPerApp:       int(maxPodsPerAppF),
		NumUsers:            int(numUsersF),
		RegistrySize:        int(registrySizeF),
		IncrementTimePeriod: 1 * time.Minute,
	}
	logrus.Infof("...start simulating...")
	c.Simulate()
	p.X, p.Y = c.Plot()

	logrus.Infof("...done simulating...")
	summary := c.Describe()
	logrus.Infof("...simulation results... %v", summary)
	fmt.Fprintf(res, "%v\n", summary)
	logrus.Infof("returning from sim run")
}

func main() {
	ps := &PlotServ{}
	listenPort := fmt.Sprintf(":%s", ps.Port())
	fmt.Printf("Listening on %s\n", listenPort)
	http.HandleFunc("/sim", ps.Run)
	http.HandleFunc("/viz", ps.drawChart)
	log.Fatal(http.ListenAndServe(listenPort, nil))
}
