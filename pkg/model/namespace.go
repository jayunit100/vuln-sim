package model

import (
	"fmt"
	"strings"

	randomdata "github.com/Pallinder/go-randomdata"
)

type Namespace struct {
	ns         string
	containers []*Container
}

var namespaces []string

func init() {
	for i := 0; i < 1000; i++ {
		namespaces[i] = fmt.Sprintf("ns-%v", strings.ToLower(randomdata.SillyName()))
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
