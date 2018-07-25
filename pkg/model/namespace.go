package model

type Namespace struct {
	ns         string
	containers []*Container
}

func (n *Namespace) isVulnerable() bool {
	for _, c := range n.containers {
		if c.image.vulns > 0 {
			//logrus.Debugf("warning: vulnerable namespace ! %v ( containers = %v ) ", c.image, len(n.containers))
			return true
		}
	}
	return false
}

// Might not really be used ?
func (n *Namespace) Delete(c *Container) {
	for i, cc := range n.containers {
		if cc.id == c.id {
			n.containers = append(n.containers[:i], n.containers[i+1:]...)
			return
		}
	}
}

// Countes total vulns in the ns.
func (n *Namespace) TotalVulns() int {
	soFar := 0
	for _, c := range n.containers {
		soFar = c.image.vulns + soFar
	}
	return soFar
}
