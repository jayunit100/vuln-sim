package model2

import (
	"testing"

	"github.com/sirupsen/logrus"
)

// NewImage returns an image.
func TestNewApp(t *testing.T) {
	app, pods := randApp(10)
	for k, v := range pods {
		logrus.Infof("%v %v %v", app, k, v)
	}
}

// This is a good test for getting the vulnerability stats to match the real world.
// Toy with the randImage() vuln returns, and look at the output.
func TestNewImage(t *testing.T) {

	foundAll := 0
	foundHigh := 0
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
			foundHigh++
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
		logrus.Infof("none: %v  low: %v, high:%v  all: %v  ANY:%v TOTAL: %v", foundNone, foundLow, foundHigh, foundAll, any, i)

		if foundAll > 0 && foundHigh > 0 && foundLow > 0 {
			return
		}
	}
}
