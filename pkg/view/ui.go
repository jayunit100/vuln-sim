package view

import (
	"fmt"
	"time"

	"github.com/gizak/termui"
	"github.com/jayunit100/vuln-sim/pkg/model3"
)

// Spacing returns the indices of the array we will use for viz.
func Spacing(data []int) []int {
	if len(data) < 20 {
		return data
	} else {
		data2 := []int{}
		for i := 0; i < 50; i++ {
			data2 = append(data2, i*len(data)/50)
		}
		return data2
	}

}

func LaunchUI(sims map[string]*model3.ClusterSim) {
	if err := termui.Init(); err != nil {
		panic(err)
	}
	defer termui.Close()
	for title, sim := range sims {
		bc := func() *termui.BarChart {
			bc := termui.NewBarChart()
			data := []int{}
			bclabels := []string{}
			vulns := Spacing(sim.Vulns)
			for i := 0; i < len(vulns); i += 1 {
				data = append(data, sim.Vulns[i])
				bclabels = append(bclabels, fmt.Sprintf("%v", time.Duration(i)*sim.TimeElapsedPerEvent(i)))
			}
			bc.BorderLabel = title + fmt.Sprintf("%v", sim.Describe())
			bc.Data = data
			bc.Width = 20
			bc.Height = 30
			bc.DataLabels = bclabels
			bc.TextColor = termui.ColorGreen
			bc.BarColor = termui.ColorRed
			bc.NumColor = termui.ColorYellow
			return bc
		}()
		termui.Body.AddRows(termui.NewRow(termui.NewCol(100, 0, bc)))
	}
	// calculate layout
	termui.Body.Align()
	termui.Render(termui.Body)
	termui.Handle("/sys/kbd/q", func(termui.Event) {
		termui.StopLoop()
	})
	termui.Loop()
}
