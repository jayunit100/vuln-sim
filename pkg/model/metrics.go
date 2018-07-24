package model

import (
	"github.com/prometheus/client_golang/prometheus"
)

var VulnsDetected prometheus.Gauge

func init() {
	VulnsDetected = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vuln-sm",
		Subsystem: "vulns",
		Name:      "vulns_detected",
		Help:      "Number of vulnerabilities detected.",
	})
}
