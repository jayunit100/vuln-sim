package util

import (
	"testing"
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
