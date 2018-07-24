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
	Name     string
	Tags     []string
	vulns    int
	contents string
}

// 1/3 of images have some vulnerabilities, http://banyanops.com/blog/analyzing-docker-hub/
var vulnsProbabilityArray = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 10, 15, 20}

// CONSTANTS
var images []*Image
var tags []string

// make 20k images to start
func init() {
	tags = strings.Split(
		",",
		"asdfweo,df,woeif,oei,oi,wodi,cowdi,cwoid,cwo,cwoei,foe,owe,cwod,cowe,cowei,woe,woe,woei,woei,2oei,dod,codi,cd,c,dc,kfk,df,sdf,e,fe,f3,5h4,g,4rf34,f24,f,5fer,ve,dc,dcw,ec,we,f3r,f3,rf,we,edce,d")
	for i := 0; i < 20000; i++ {
		// randomly make a name for this image.
		images[i] = NewImage(strings.ToTitle(randomdata.SillyName()))
		// randomly select how many vulnerabilities this image has.
		images[i].vulns = vulnsProbabilityArray[rand.Int()%len(vulnsProbabilityArray)]

		//quick and dirty way to find two arbitary non same tags
		for {
			tt := make(map[string]int)
			tt[tags[(rand.Int())%len(tags)]] = 1
			tt[tags[(rand.Int())%len(tags)]] = 2
			if len(tt) > 1 {
				for t, _ := range tt {
					images[i].Tags = append(images[i].Tags, t)
				}
				break
			}
		}
	}
}

func (i *Image) Sha() string {
	sha := fmt.Sprintf("%v-%v-%v", i.Name, time.Now(), rand.Intn(2000))
	return sha
}

// Sibling returns a random 'upgraded' image
func (i *Image) Sibling() *Image {
	choices := []*Image{}
	for _, ii := range images {
		if ii.Name == i.Name {
			choices = append(choices, ii)
		}
	}
	return choices[rand.Int()%len(choices)]
}

// NewImage returns an image.
func NewImage(n string) *Image {
	i := &Image{}
	i.Name = n
	i.Tags = []string{}
	i.Tags = append(i.Tags, fmt.Sprintf("tag-%v", time.Now().Format("Mon Jan 2 12:00:00 2006")))
	util.AdvanceClock(1 * time.Second)
	return i
}

// randImage returns a random image from a fixed set of images .
func randImage() *Image {
	return images[rand.Int()%len(lexicon)]
}
