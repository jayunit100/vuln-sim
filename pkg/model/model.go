package model

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	randomdata "github.com/Pallinder/go-randomdata"
	log "github.com/sirupsen/logrus"

	util "github.com/jayunit100/vuln-sim/pkg/util"
)

type Datacenter struct {
	namespaces   []*Namespace
	creationRate time.Duration
	updateRate   time.Duration
	deletionRate time.Duration
	operations   chan func()
}

func init() {
	log.SetLevel(log.InfoLevel)
	log.Debugf("Loading...")
}

// VulnerableImagesBySha returns all vulnerable images in the datacenter, in actuality.
func (d *Datacenter) VulnerableImagesBySha() []string {
	images := []string{}
	log.Debugf(fmt.Sprintf("v # of namespaces %v", len(d.namespaces)))
	for _, n := range d.namespaces {
		for _, c := range n.containers {
			if c.image.vulns > 0 {
				images = append(images, c.image.Sha())
			}
		}
	}
	return images
}

// VulnerableNamespaces returns all vulnerable ns
func (d *Datacenter) VulnerableNamespaces() []string {
	vulnNs := []string{}
	log.Debugf(fmt.Sprintf("v # of namespaces %v", len(d.namespaces)))
	for _, n := range d.namespaces {
		if n.isVulnerable() {
			vulnNs = append(vulnNs, n.ns)
		}
	}
	return vulnNs
}

// DO NOT CALL, use cache instead...
func (d *Datacenter) Containers() []*Container {
	containers := []*Container{}
	for _, n := range d.namespaces {
		for _, c := range n.containers {
			containers = append(containers, c)
		}
	}
	return containers
}

func (d *Datacenter) newApp() {
	ns := &Namespace{
		ns: fmt.Sprintf("ns-%v", strings.ToLower(randomdata.SillyName())),
	}
	vulnImages := 0
	safeImages := 0

	// max containers = 30
	numContainers := rand.Intn(5) + 1
	for i := 0; i < numContainers; i++ {
		c := &Container{}
		// 1 in 7 containers is exposed.
		c.exposed = rand.Intn(10)%7 == 0
		c.image = randImage()
		ns.containers = append(ns.containers, c)
		if c.image.vulns > 0 {
			vulnImages++
		} else {
			safeImages++
		}
	}
	d.namespaces = append(d.namespaces, ns)
}

// deleteApp not thread safe, grab a mutex first!
func (d *Datacenter) deleteApp() {
	log.Debugf(fmt.Sprintf(" d # of namespaces %v", len(d.namespaces)))

	if len(d.namespaces) == 0 {
		panic("Can't delete an app when no namespaces !")
	}

	newNs := []*Namespace{}
	for i, s := range d.namespaces {
		if i > 0 {
			newNs = append(newNs, s)
		}
	}
	d.namespaces = newNs
}

func NewDs() *Datacenter {
	d := &Datacenter{}
	d.operations = make(chan func(), 100)
	// work queue... every data cetner operation serialized into this thread.
	go func() {
		for {
			f := <-d.operations
			f()
		}
	}()
	return d
}

var vulns map[string]string

// Simulate simulates cluster images that come and go.
func Simulate(maxNS int, maxContainers int) {
	vulns = make(map[string]string)
	d := NewDs()
	steady := 1000
	// seed the cluster w/ 1000 namespaces
	for i := 0; i < steady; i++ {
		d.newApp()
	}
	sims := 0
	adds := 0
	deletes := 0
	scanner := &SecurityScanner{}
	for {
		// cluster size varies 10% up or down, by adding up to
		// 10% * steadystate add or delete operations in chunks.
		if len(d.namespaces) < steady || rand.Intn(10) < 4 {
			for i := 0; i < rand.Intn(steady/10); i++ {
				d.operations <- d.newApp
				adds++
			}
		} else {
			d.operations <- d.deleteApp
			for i := 0; i < rand.Intn(steady/10); i++ {
				if len(d.namespaces) > steady/10 { // safegaurd
					d.operations <- d.deleteApp
					deletes++
				} else {
					log.Warn("WARNING: CLUSTER SIZE GOT SMALL! SKIPPED DELETE SIMULATION.")
				}
			}
		}
		sims++
		vulnNs := d.VulnerableNamespaces()
		vulnImg := d.VulnerableImagesBySha()

		fmt.Println("*********************************************************")
		fmt.Println(fmt.Sprintf("adds:%v deletes:%v total:%v queue:%v", adds, deletes, sims, len(d.operations)))
		fmt.Println(fmt.Sprintf("namespaces %v", len(d.namespaces)))
		fmt.Println(fmt.Sprintf("containers total : %v", len(d.Containers())))
		fmt.Println(fmt.Sprintf("vulnerable images %v", len(vulnImg)))
		ImagesM.WithLabelValues("true").Set(float64(len(vulnImg)))

		fmt.Println(fmt.Sprintf("vulnerable namespaces %v", len(vulnNs)))
		fmt.Println(fmt.Sprintf("time in days so far: %v , simulations: %v", (util.SimulatedTimeSoFar().Hours() / 24), sims))
		util.AdvanceClock(1 * time.Hour)

		fmt.Println("Starting scan simulation !")
		// we've got one hour to scan stuff...
		maxMinutes := 60.0
		var minutes float64
		scanned := 0
		for _, c := range d.Containers() {
			vuln, t := scanner.scanGetVuln(c.image)

			if c.image.vulns > 0 {
				ImagesM.WithLabelValues("true").Inc()
			} else {
				ImagesM.WithLabelValues("false").Inc()
			}

			if vuln {
				ImagesScannedM.WithLabelValues("true").Inc()
				vulns[c.image.Sha()] = "..."
			} else {
				ImagesScannedM.WithLabelValues("false").Inc()

			}
			scanned++
			minutes = minutes + t.Minutes()
			util.AdvanceClock(t)
			if minutes > maxMinutes {
				logrus.Infof("breaking! got through %v in one minute. vulns %v", scanned, len(vulns))
				break
			}
		}
		//logrus.Infof("threats: %v", vulns)
		for _, c := range d.VulnerableImagesBySha() {
			if _, ok := vulns[c]; ok {
				ThreatsM.WithLabelValues("true").Inc()
			} else {
				//logrus.Infof("didnt see %v in the vulns array !", c)
				ThreatsM.WithLabelValues("false").Inc()
			}
		}
		time.Sleep(5 * time.Second)
	}
}
