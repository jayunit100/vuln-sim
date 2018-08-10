package model3

import (
	"fmt"
	"math/rand"

	randomdata "github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

type Registry struct {
	Images map[string]*Image
}

func NewImage(baseName string, tag []string) *Image {
	logrus.Infof("%v %v %v", util.RandIntFromDistribution(5, 10), util.RandIntFromDistribution(5, 10), util.RandIntFromDistribution(5, 10))

	img := &Image{
		SHA:          fmt.Sprintf("%v-%v", rand.Float32(), randomdata.PostalCode("")),
		Name:         baseName,
		Tags:         tag,
		HasLowVulns:  util.RandIntFromDistribution(10, 5) < 9,
		HasMedVulns:  util.RandIntFromDistribution(10, 5) < 8,
		HasHighVulns: util.RandIntFromDistribution(10, 5) < 7,
	}
	return img
}

func NewRegistry(maxBaseNames int, maxImages int) *Registry {
	r := &Registry{}
	r.Images = make(map[string]*Image)
	// make a bunch of base images...
	for i := 0; i < maxBaseNames; i++ {
		fmt.Printf(fmt.Sprintf("making new image %v", i))
		i := NewImage(randomdata.SillyName(), []string{"latest"})
		r.Images[i.SHA] = i
	}

	done := func() bool {
		return len(r.Images) >= maxImages
	}

	version := 0.0
	for !done() {
		version = version + 1
		for _, v := range r.Images {
			if !done() {
				i := NewImage(v.Name, []string{fmt.Sprintf("%v", version)})
				fmt.Printf(fmt.Sprintf("making new image %v / %v \n", len(r.Images), maxImages))
				r.Images[i.SHA] = i
			} else {
				return r
			}
		}
	}
	return r
}
