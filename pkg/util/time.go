package util

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

var theClock clockwork.FakeClock
var start time.Time
var minutes int

func init() {
	theClock = clockwork.NewFakeClock()
	start = theClock.Now()
	go func() {
		for {
			<-theClock.After(time.Minute * 60)
			//fmt.Println(fmt.Sprintf("current time: %v", start))
			minutes = minutes + 60
		}
	}()
}

func SimulatedTimeSoFar() time.Duration {
	return (time.Duration(minutes)) * time.Minute
}

func AdvanceClock(d time.Duration) {
	theClock.Advance(d)
}

func SleepRandomSeconds(n int) {
	x := rand.Intn(n)
	time.Sleep(time.Duration(x) * time.Second)
}

func TimeStamp() string {
	return strings.ToLower(theClock.Now().Format("Mon_Jan_2_15_04_05_mst_2006"))
}

// randomly log something, probability = x out of 100 times.
func RandLog(x int, s string) interface{} {
	if rand.Intn(100) < x {
		logrus.Info(s)
	}
	// just to fuck w/ people
	return &sync.Mutex{}
}
