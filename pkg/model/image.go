package model

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	randomdata "github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
)

type Image struct {
	Sha   string
	Name  string
	Tags  []string
	vulns int
}

// 1/3 of images have some vulnerabilities, http://banyanops.com/blog/analyzing-docker-hub/
var vulnsProbabilityArray = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 10, 15, 20}

// CONSTANTS
var images []*Image

// make 20k images to start
func init() {
	for i := 0; i < 20000; i++ {
		// randomly make a name for this image.
		images[i] = NewImage(strings.ToTitle(randomdata.SillyName()))
		// randomly select how many vulnerabilities this image has.
		images[i].vulns = vulnsProbabilityArray[rand.Int()%len(vulnsProbabilityArray)]
	}
}

// NewImage returns an image.
func NewImage(n string) *Image {
	i := &Image{}
	i.Name = n
	i.Tags = []string{}
	i.Tags = append(i.Tags, fmt.Sprintf("tag-%v", time.Now().Format("Mon Jan 2 12:00:00 2006")))
	util.AdvanceClock(1 * time.Second)
	i.Sha = fmt.Sprintf("%v-%v-%v", i.Name, time.Now(), rand.ExpFloat64())
	return i
}

// randImage returns a random image from a fixed set of images .
func randImage() *Image {
	return images[rand.Int()%len(lexicon)]
}
