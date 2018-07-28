package model2

import (
	"strings"

	"github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

type Img struct {
	L bool
	M bool
	H bool
	K int32
}

// Low, medium, high vulnerabilities, (image name = key)
func randImage() *Img {
	l, m, h, id := func() (bool, bool, bool, int32) {
		key := int32(util.RandIntFromDistribution(1000*1000, 10000))
		if key < 1000000+8000 {
			return false, false, false, key
		}
		if key < 1000000+11000 {
			return true, false, false, key
		}
		if key < 1000000+1200 {
			return true, true, false, key
		}
		if key < 1000000+17000 {
			return false, false, true, key
		}
		return true, true, true, key
	}()
	return &Img{l, m, h, id}
}

// randApp returns an app, which is just a map of key->image.
// app size is normally distributed (0->10)
func randApp(max_pods int) (string, map[int32]*Img) {
	pods := util.RandIntFromDistribution(max_pods, max_pods/4)
	app := map[int32]*Img{}
	iter := 0
	// i.e. 'keep making new unique images until we have 8 of them'
	for {
		i := randImage()
		logrus.Infof("image: %v  / %v", i.K, pods)
		app[i.K] = i
		if len(app) == pods {
			return strings.ToLower(randomdata.SillyName()), app
		}
		iter++
		if iter > pods+100 {
			panic("something went horribly wrong when getting a random list of pods !")
		}
	}
}
