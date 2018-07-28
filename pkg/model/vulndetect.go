package model

import (
	"time"
)

type SecurityScanner struct {
}

var scans map[string]bool

// scan simulates scanning something.
func (n *SecurityScanner) scanGetVuln(i *Image) (bool, time.Duration) {
	if vuln, ok := scans[i.Sha()]; ok {
		// return the response for image already seen.. 5 millisecond latency.
		return vuln, (time.Duration(5)) * time.Millisecond
	}

	// Scanning one container, every 3 seconds.
	// -> hits SLA for 10% churn, per hour, 1000 node cluster.

	return i.vulns > 0, 3 * time.Second
}
