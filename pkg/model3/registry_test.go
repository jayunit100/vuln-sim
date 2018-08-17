package model3

import (
	"testing"

	"github.com/jayunit100/vuln-sim/pkg/util"
	"github.com/sirupsen/logrus"
)

func TestRegNamesAndSize(t *testing.T) {
	r := NewRegistry(100, 1000)
	baseImages := make(map[string]int)
	for k, v := range r.Images {
		logrus.Infof("%v %v", r.Images[k], v)
		baseImages[v.Name] = 1
	}
	if len(r.Images) == 1000 && len(baseImages) == 100 {
		return
	} else {
		t.Logf("got wrong number of images ! (expected 1000 total, got %v) (expected 100 bases, got %v)", len(r.Images), len(baseImages))
		t.Fail()
	}
}

func TestRand(t *testing.T) {
	lowNumfound := false
	for i := 0; i < 10; i++ {
		x := util.RandIntFromDistribution(5, 10)
		logrus.Infof("%v", x)
		if x == 0 {
			lowNumfound = true
		}
	}
	if !lowNumfound {
		t.Log("never found 0 in a distro of 5 that varies in +/- 10")
		t.Fail()
	}

	min := 10000
	for i := 0; i < 100; i++ {
		x := util.RandIntFromDistribution(100, 50)
		if min > x {
			min = x
		}
		logrus.Infof("%v %v", x, min)
	}
}

func TestRegVulns(t *testing.T) {
	maxImages := 20000
	bases := 1000
	r := NewRegistry(bases, maxImages)

	var h int
	var m int
	var l int
	for _, v := range r.Images {
		if v.HasHighVulns {
			h++
		}
		if v.HasMedVulns {
			m++
		}
		if v.HasLowVulns {
			l++
		}
		if len(v.Tags) < 1 {
			logrus.Infof("not enough tags! %v", v.Tags)
			t.Fail()
		}
	}
	if h == 0 || m == 0 || l == 0 {
		t.Logf("Failure, 0's found: %v %v %v", l, m, h)
		t.Fail()
	}
	if float32(h)/float32(maxImages) >= .3 || float32(m/maxImages) >= .3 || float32(l/maxImages) > .3 {
		t.Logf("Failure, too many vulns found: %v %v %v", l, m, h)
		t.Fail()
	}
	if float32(h)/float32(maxImages) < .25 {
		t.Logf("Failure, NOT ENOUGH vulns found:  %v/%v = %v", h, maxImages, float32(h)/float32(maxImages))
		t.Fail()
	}
}
