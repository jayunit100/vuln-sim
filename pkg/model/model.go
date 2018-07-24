package model

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	randomdata "github.com/Pallinder/go-randomdata"

	util "github.com/jayunit100/vuln-sim/pkg/util"
)

type Datacenter struct {
	namespaces   []*Namespace
	creationRate time.Duration
	updateRate   time.Duration
	deletionRate time.Duration
}

var nsMutate *sync.Mutex

func init() {
	nsMutate = &sync.Mutex{}
}

// VulnerableImagesBySha returns all vulnerable images in the datacenter, in actuality.
func (d *Datacenter) VulnerableImagesBySha() []string {
	nsMutate.Lock()

	images := []string{}
	for _, n := range d.namespaces {
		for _, c := range n.containers {
			if c.image.vulns > 0 {
				images = append(images, c.image.Sha())
			}
		}
	}
	nsMutate.Unlock()

	return images
}

func (d *Datacenter) newApp() {
	nsMutate.Lock()
	ns := &Namespace{
		ns: fmt.Sprintf("ns-%v", strings.ToLower(randomdata.SillyName())),
	}
	// max containers = 30
	numContainers := rand.Intn(30) + 1
	for i := 0; i < numContainers; i++ {
		c := &Container{}
		// 1 in 7 containers is exposed.
		c.exposed = rand.Intn(10)%7 == 0
		c.image = images[rand.Intn(len(images))]
	}
	d.namespaces = append(d.namespaces, ns)
	fmt.Println(fmt.Sprintf("Created ns %v with %v containers vulns (total) %v", ns.ns, len(ns.containers), ns.TotalVulns()))
	nsMutate.Unlock()

}

func (d *Datacenter) deleteApp() {
	nsMutate.Lock()

	i := rand.Intn(len(d.namespaces))
	d.namespaces = append(d.namespaces[:i], d.namespaces[i+1:]...)
	nsMutate.Unlock()

}

// Simulate simulates cluster images that come and go.
func (d *Datacenter) Simulate(maxNS int, maxContainers int) {
	s := &sync.Mutex{}
	do := func(run func()) {
		s.Lock()
		run()
		s.Unlock()
	}
	for {
		// app Creation
		go func() {
			util.AdvanceClock(d.creationRate)
			do(d.newApp)
		}()

		// app Destruction. which also serves as bulk container rev'ing.
		go func() {
			util.AdvanceClock(d.deletionRate)
			do(d.deleteApp)
		}()

		util.AdvanceClock(1 * time.Second)
	}
}
