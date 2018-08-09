package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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
				Label: fmt.Sprintf("%v", p.X[i]),
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

func main() {
	c := &model2.ClusterSim{
		ChurnProbability: .10,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		TimePeriod:       1 * time.Minute,
	}
	model2.Simulate(c)
	_, x, y := c.Plot()

	ps := &PlotServ{}
	ps.X = x
	ps.Y = y

	listenPort := fmt.Sprintf(":%s", ps.Port())
	fmt.Printf("Listening on %s\n", listenPort)
	http.HandleFunc("/", ps.drawChart)
	log.Fatal(http.ListenAndServe(listenPort, nil))

}
