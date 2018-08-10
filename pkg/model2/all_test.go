package model2

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// NewImage returns an image.
func TestNewApp(t *testing.T) {
	containersfound := map[int32]int{}
	appsCreated := 0
	containersCreated := 0

	for {
		_, pods := randApp(10)
		appsCreated++

		for _, v := range pods {
			containersCreated++
			containersfound[v.K] = containersfound[v.K] + 1
			if containersfound[v.K] == 2 {
				logrus.Infof("Found a repeat %v !", v.K)
				logrus.Infof("iter %v: %v", appsCreated, containersfound)

				return
			}
		}
		logrus.Infof("apps created so far: %v, containers %v", appsCreated, containersCreated)
		if appsCreated > 1000 {
			t.Log("Made 1000 apps but didnt see a single container reused!")
			logrus.Infof("%v", containersfound)
			time.Sleep(1 * time.Second)
			t.Fail()
			return
		}
		logrus.Infof("looping... %v %v", appsCreated, len(containersfound))
	}
}

// This is a good test for getting the vulnerability stats to match the real world.
// Toy with the randImage() vuln returns, and look at the output.
func TestNewImage(t *testing.T) {
	foundAll := 0
	foundHighOnly := 0
	foundLow := 0
	foundNone := 0
	any := 0
	i := 1
	for {
		r := randImage()
		if r.L || r.M || r.H {
			any++
		}
		if r.L && r.M && r.H {
			foundAll++
		}
		if r.H && !r.M && !r.L {
			foundHighOnly++
		}
		if !r.H && !r.M && r.L {
			foundLow++
		}
		if !r.H && !r.M && !r.L {
			foundNone++
		}
		i = i + 1
		if i > 1000 {
			t.Errorf("Too many trials, some situations arent being generated.")
			t.Fail()
			return
		}
		logrus.Infof("none: %v  low: %v, high:%v  all: %v  ANY:%v TOTAL: %v", foundNone, foundLow, foundHighOnly, foundAll, any, i)

		if foundAll > 0 && foundHighOnly > 0 && foundLow > 0 {
			return
		}
	}
}
