package model2

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Generic *prometheus.GaugeVec

func init() {

	Generic = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "generic",
		Help:      "generic counters",
	}, []string{"Days", "Churn", "Adds", "Deletes"})

}
func init() {
	prometheus.MustRegister(Generic)

	logrus.Infof("starting prometheus http")
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		http.ListenAndServe(":9091", nil)
	}()
}
