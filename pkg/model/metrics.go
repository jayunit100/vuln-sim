package model

import (
	"github.com/prometheus/client_golang/prometheus"
)

var vulnsDetected prometheus.Gauge

func init() {
	vulnsDetected = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vuln-sm",
		Subsystem: "vulns",
		Name:      "vulns_detected",
		Help:      "Number of vulnerabilities detected.",
	})
}
