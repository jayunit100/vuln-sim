package model2

import (
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/Pallinder/go-randomdata"
	"github.com/jayunit100/vuln-sim/pkg/util"
)

type Img struct {
	L bool
	M bool
	H bool
	K int32
}

// randImage creates an image with a "SHA" as an integer "key" for simplicity, since
// this is just for simulations.  When the seed varies, it simulates the addition of new
// containers to a system, since the range of integers is related to the seed value.
func randImage(registrySize int) *Img {
	// This function computes vulnarbility for an image.
	// The primary key of the image is an int32.
	// The values below are calibrated for test outputs.

	// The below values are calibrated for 'reasonable' vuln. stats, east to modify
	// and then rerun the unit tests and check output.
	simpleCalib := []int{
		registrySize,
		registrySize + registrySize/50,
		registrySize + registrySize/40,
	}

	l, m, h, id := func() (bool, bool, bool, int) {
		key := util.RandIntFromDistribution(registrySize, registrySize/100)
		if key < simpleCalib[0] {
			return false, false, false, key
		}
		if key < simpleCalib[1] {
			return true, false, false, key
		}
		if key < simpleCalib[2] {
			return false, false, true, key
		}
		return true, true, true, key
	}()
	return &Img{l, m, h, int32(id)}
}

// randApp returns an app, which is just a map of key->image.
// app size is normally distributed (0->10)
func randApp(max_pods int, regSize int) (string, map[int32]*Img) {
	pods := util.RandIntFromDistribution(max_pods, max_pods/2) + 100
	app := map[int32]*Img{}
	iter := 0
	// i.e. 'keep making new unique images until we have 8 of them'
	for {
		i := randImage(regSize)
		//logrus.Infof("image: %v  / %v", i.K, pods)
		app[i.K] = i
		if len(app) == pods {
			return strings.ToLower(randomdata.SillyName()), app
		}
		iter++
		if iter > pods+100 {
			logrus.Fatalf("app pods: %v, desired: %v, iterations: %v... max_pods: %v", len(app), pods, iter, max_pods)
			panic("something went horribly wrong when getting a random list of pods !")
		}
	}
}
