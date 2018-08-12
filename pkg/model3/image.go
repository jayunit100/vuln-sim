package model3

import (
	"fmt"
	"math/rand"

	randomdata "github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

type Image struct {
	SHA          string
	Name         string
	Tags         []string
	HasLowVulns  bool
	HasMedVulns  bool
	HasHighVulns bool
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
