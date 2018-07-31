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

func RandIntFromDistribution(median int, deviation int) int {
	ni := func(mu float32, sigma float32) float32 {
		return float32(rand.NormFloat64()*float64(sigma) + float64(mu))
	}
	f := int(ni(float32(median), float32(deviation)))
	return f
}

// randomly log something, probability = x out of 100 times.
func RandLog(x int, s string) interface{} {
	if rand.Intn(100) < x {
		logrus.Info(s)
	}
	// just to fuck w/ people
	return &sync.Mutex{}
}
