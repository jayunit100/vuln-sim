package model2

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Generic *prometheus.GaugeVec
var VulnsMetric *prometheus.GaugeVec

func init() {

	Generic = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "generic",
		Help:      "generic counters",
	}, []string{"Operation"})
	VulnsMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "containers",
		Help:      "containers vulns",
	}, []string{"Type"})
}
func init() {
	prometheus.MustRegister(Generic)
	prometheus.MustRegister(VulnsMetric)

	logrus.Infof("starting prometheus http")
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		http.ListenAndServe(":9091", nil)
	}()
}
