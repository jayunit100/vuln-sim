package model

import (
	"time"

	u "github.com/jayunit100/vuln-sim/pkg/util"
)

// Vuln detect is a tool that detects vulnerabilities...
// ... generically representing a security solution which
// might inspect containers or ports or ...

type VulnDetect struct {
	// map of projects -> vulnerabilities.
	Vulns map[string]int
}

func (v *VulnDetect) Scan(i *Image) {
	u.AdvanceClock(2 * time.Minute)
	v.Vulns[i.Sha] = i.vulns
}
