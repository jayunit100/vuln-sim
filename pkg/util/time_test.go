package util

import (
	"testing"

	"github.com/sirupsen/logrus"
)

// NewImage returns an image.
func TestNewApp(t *testing.T) {
	_49 := 0
	_50 := 0
	for i := 0; i < 30; i++ {
		if 50 == RandIntFromDistribution(50, 1) {
			_50++
		}
		if 49 == RandIntFromDistribution(50, 1) {
			_49++
		}
	}
	if _50 > 1 && 49 > 1 {
		return
	}
	t.Fail()
}

func TestMapNums(t *testing.T) {
	m := MapNums([]int{100, 101, 202, 303, 440, 500, 695, 712, 812, 949}, 4)
	for k, v := range m {
		logrus.Infof("%v %v", k, v)
	}
	if len(m) != 5 {
		t.Fail()
	}
}
