package model

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	randomdata "github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
	log "github.com/sirupsen/logrus"
)

type Image struct {
	Name     string
	Tags     []string
	vulns    int
	contents string
}

// 1/3 of images have some vulnerabilities, http://banyanops.com/blog/analyzing-docker-hub/
var vulnsProbabilityArray = []int{}

// CONSTANTS
var images map[string]*Image
var tags []string

// make 20k images to start
func init() {
	imagesSeen = make(map[string]string)
	for i := 0; i < 100; i++ {
		if i%3 == 0 {
			vulnsProbabilityArray = append(vulnsProbabilityArray, 1)
		} else {
			vulnsProbabilityArray = append(vulnsProbabilityArray, 0)
		}
	}
	log.Infof("vulns: %v ", vulnsProbabilityArray)
	images = make(map[string]*Image)
	tags = strings.Split(
		"asdfweo,df,woeif,oei,oi,wodi,cowdi,cwoid,cwo,cwoei,foe,owe,cwod,cowe,cowei,woe,woe,woei,woei,2oei,dod,codi,cd,c,dc,kfk,df,sdf,e,fe,f3,5h4,g,4rf34,f24,f,5fer,ve,dc,dcw,ec,we,f3r,f3,rf,we,edce,d", ",")
	for i := 0; i < 10000; i++ {
		// randomly make a name for this image.
		img := &Image{}
		img.contents = fmt.Sprintf("%v", rand.Intn(10000000))
		img.Name = strings.ToTitle(randomdata.SillyName())
		img.Tags = []string{}
		img.Tags = append(img.Tags, fmt.Sprintf("tag-%v", time.Now().Format("Mon Jan 2 12:00:00 2006")))

		// randomly select how many vulnerabilities this image has.
		img.vulns = vulnsProbabilityArray[rand.Int()%len(vulnsProbabilityArray)]
		if i%500 == 0 {
			util.RandLog(1, fmt.Sprintf("vulnerabilities in image: %v", img.vulns))
		}
		//quick and dirty infinite loop  way to find two arbitary non same tags
		func() {
			for {
				tt := make(map[string]int)
				tt[tags[(rand.Int())%len(tags)]] = 1
				tt[tags[(rand.Int())%len(tags)]] = 2
				tt[tags[(rand.Int())%len(tags)]] = 3

				if len(tt) > 1 {
					for t, _ := range tt {
						img.Tags = append(img.Tags, t)
					}
					return
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		}()
		images[img.Name] = img
	}
}

// TODO make it a constant.
func (i *Image) Sha() string {
	sha := fmt.Sprintf("%v-%v", i.Name, i.contents)
	return sha
}

var imagesSeen map[string]string

// randImage returns a random image from a fixed set of images .
func randImage() *Image {
	i := randStringMapKey(images)
	imagesSeen[i] = "..."
	if len(imagesSeen) == len(images) {
		panic("all images seen. simulation complete.")
	}
	return images[i]
}

func randStringMapKey(m map[string]*Image) string {
	i := rand.Intn(len(m))
	for k := range m {
		if i == 0 {
			return k
		}
		i--
	}
	panic("no key!")
}
