package main

import (
	"time"

	"github.com/jayunit100/vuln-sim/pkg/model"
) // <- ui shortcut, optional

func main() {
	go func() {
		model.Simulate(100, 100)
	}()
	for {
		time.Sleep(1 * time.Minute)
	}
	// event handler...
}
