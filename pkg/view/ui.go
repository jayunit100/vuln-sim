package view

import (
	"fmt"
	"time"

	"github.com/gizak/termui"
	"github.com/jayunit100/vuln-sim/pkg/model3"
	"github.com/jayunit100/vuln-sim/pkg/util"
)

func LaunchUI(sims map[string]*model3.ClusterSim) {

	// must happen b4 you do other termui actions.
	if err := termui.Init(); err != nil {
		panic(err)
	}
	defer termui.Close()

	for title, sim := range sims {
		// build a new horizontally spanning chart
		bc := func() *termui.BarChart {
			bc := termui.NewBarChart()
			data := []int{}
			bclabels := []string{}
			sortedEvents, vulns := util.MapNums(sim.Vulns, 40)
			// i is the index of the event in the timeseries of the granular events.
			// vulnValueMapped is the *VALUE*.  Only certain 'i' values are retained.
			for _, eventID := range sortedEvents {
				data = append(data, vulns[eventID])
				bclabels = append(bclabels, fmt.Sprintf("%v[%v]", eventID, time.Duration(eventID)*sim.TimeElapsedPerEvent(eventID)))
			}
			bc.BarWidth = 15
			bc.BorderLabel = title + fmt.Sprintf("%v", sim.Describe())
			bc.Data = data
			bc.Width = 100
			bc.Height = 20
			bc.DataLabels = bclabels
			bc.TextColor = termui.ColorGreen
			bc.BarColor = termui.ColorRed
			bc.NumColor = termui.ColorYellow
			return bc
		}()
		termui.Body.AddRows(termui.NewRow(termui.NewCol(200, 0, bc)))
	}

	// calculate layout
	termui.Body.Align()
	termui.Render(termui.Body)
	termui.Handle("/sys/kbd/q", func(termui.Event) {
		termui.StopLoop()
	})
	termui.Loop()
}
