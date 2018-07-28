package model2

import "math/rand"

type ClusterSim struct {
	NumUsers           int
	MaxPods            int
	ChurnProbability   float32
	ImgVulnProbability float32
	Day                int
	StateApp           map[string]map[int32]*Img
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
	c.Day = 0
	if c.ImgVulnProbability == 0.0 {
		panic("cant run w/ 0.0 vuln probability")
	}

	// now, populate...
	for {
		Generic.WithLabelValues("Adds").Inc()
		app, pods := randApp(c.MaxPods) // map[int32]*Img
		c.StateApp[app] = pods
		if len(c.StateApp) == c.NumUsers {
			return
		}
	}
}

// Inc Increments the state of the cluster by one day.
func (c *ClusterSim) IncrementDay() {
	Generic.WithLabelValues("Apps").Set(float64(len(c.StateApp)))
	// initially the length of 'state' is # the initial users.
	deletes := []string{}
	adds := map[string]map[int32]*Img{}

	// (1) plan all the changes that happened in this time span, w/o mutating anything.
	for app, _ := range c.StateApp {
		// churn event !
		if c.ChurnProbability > rand.Float32() {
			Generic.WithLabelValues("Churn").Inc()
			// either add or delete something.
			if rand.Intn(3) < 1 {
				deletes = append(deletes, app)
			} else {
				newApp, newPods := randApp(c.MaxPods)
				adds[newApp] = newPods
			}
		}
	}
	// (2) now, do all the map mutation actions...
	for _, app := range deletes {
		Generic.WithLabelValues("Deletes").Inc()
		delete(c.StateApp, app)
	}
	for app, pods := range adds {
		Generic.WithLabelValues("Adds").Inc()
		c.StateApp[app] = pods
	}
	Generic.WithLabelValues("Days").Inc()
}
