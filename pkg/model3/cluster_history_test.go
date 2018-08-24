package model3

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestHistoryKeepVulns(t *testing.T) {
	h := History{}
	img1 := &Image{
		HasHighVulns: true,
		SHA:          "img1",
	}
	img2 := &Image{
		HasHighVulns: true,
		SHA:          "img2",
	}

	logrus.Infof("create")

	h.ApplyCreate("ns1", []*Image{img1, img2})
	logrus.Infof("next")

	h.Next()

	logrus.Infof("create")

	h.ApplyCreate("ns2", []*Image{img1, img2})

	logrus.Infof("next 1")

	h.Next()
	logrus.Infof("next 2")

	h.Next()

	if len(h.ImagesAt(len(h.State)-1)) == 0 {
		logrus.Warn("Create is broken ")
		t.Fail()
	}

	logrus.Infof("Before delete images: %v", h.ImagesAt(len(h.State)-1))

	logrus.Infof("DESTR 1")

	h.ApplyDestroy("ns2", []*Image{img1, img2})
	logrus.Infof("DESTR 2")

	h.ApplyDestroy("ns1", []*Image{img1, img2})

	h.Next()

	logrus.Infof("final images: %v", h.ImagesAt(len(h.State)-1))

	if len(h.ImagesAt(len(h.State)-1)) != 0 {
		logrus.Warn("Delete is broken ")
		t.Fail()
	}
}
