package util

import (
	"strings"
	"time"

	"github.com/jonboulle/clockwork"
)

var theClock clockwork.Clock

func init() {
	theClock = clockwork.NewFakeClock()
}

func AdvanceClock(d time.Duration) {
	theClock.Sleep(d)
}

func TimeStamp() string {
	return strings.ToLower(theClock.Now().Format("Mon_Jan_2_15_04_05_mst_2006"))
}
