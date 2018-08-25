package view

import (
	"fmt"
	"time"

	"github.com/gizak/termui"
	"github.com/jayunit100/vuln-sim/pkg/model3"
	"github.com/sirupsen/logrus"
)

func LaunchUI(sims map[string]*model3.ClusterSim) {

	vulns := map[string][]int{}
	eventIDs := map[string][]int{}

	for title, sim := range sims {
		sims[title] = sim
		vulns[title] = []int{}
		eventIDs[title] = []int{}
		for i := 0; i < sim.TotalActions(); i += sim.TotalActions() / 40 {
			logrus.Infof("%v out of %v", i, sim.TotalActions()/40)
			vulns[title] = append(vulns[title], sim.VulnsAt(i))
			eventIDs[title] = append(eventIDs[title], i)
		}
	}

	// must happen b4 you do other termui actions.
	if err := termui.Init(); err != nil {
		panic(err)
	}
	defer termui.Close()

	for title, vulnsArray := range vulns {
		sim := sims[title]
		// build a new horizontally spanning chart
		bcc := func() *termui.BarChart {
			termui.Render(termui.NewPar(fmt.Sprintf("asdf %v %v", "a", "b")))

			bc := termui.NewBarChart()
			data := []int{}
			bclabels := []string{}

			// i is the index of the event in the timeseries of the granular events.
			// vulnValueMapped is the *VALUE*.  Only certain 'i' values are retained.
			for i, vuln := range vulnsArray {
				eventID := eventIDs[title][i]
				data = append(data, vuln)
				bclabels = append(bclabels, fmt.Sprintf("%v[%v]", eventID, time.Duration(eventID)*sim.TimeElapsedPerEvent(eventID)))
			}
			bc.BarWidth = 15
			bc.Data = data
			bc.Width = 100
			bc.Height = 20
			bc.DataLabels = bclabels
			bc.TextColor = termui.ColorGreen
			bc.BarColor = termui.ColorRed
			bc.NumColor = termui.ColorYellow
			return bc
		}()
		termui.Body.AddRows(termui.NewRow(termui.NewCol(200, 0, bcc)))
	}

	// calculate layout
	termui.Body.Align()
	termui.Render(termui.Body)
	termui.Handle("/sys/kbd/q", func(termui.Event) {
		termui.StopLoop()
	})
	termui.Loop()
}
