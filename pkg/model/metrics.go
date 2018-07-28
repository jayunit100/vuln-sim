package model

import (
	"github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
)

var NamespacesM *prometheus.GaugeVec
var ImagesM *prometheus.GaugeVec
var NamespacesScannedM *prometheus.GaugeVec
var ImagesScannedM *prometheus.GaugeVec

var ThreatsM *prometheus.GaugeVec

func init() {

	NamespacesM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "namespaces",
		Help:      "total namespaces that are vuln",
	}, []string{"is_vuln"})
	ImagesM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "images",
		Help:      "total images vuln",
	}, []string{"is_vuln"})
	NamespacesScannedM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "namespaces_scanned",
		Help:      "total ns scanned",
	}, []string{"is_vuln"})
	ImagesScannedM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "containers_scanned",
		Help:      "total images scanned",
	}, []string{"is_vuln"})
	ThreatsM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vuln",
		Subsystem: "",
		Name:      "threats",
		Help:      "threats",
	}, []string{"seen"})

}
func init() {
	prometheus.MustRegister(NamespacesM)
	prometheus.MustRegister(ImagesM)
	prometheus.MustRegister(NamespacesScannedM)
	prometheus.MustRegister(ImagesScannedM)
	prometheus.MustRegister(ThreatsM)

	logrus.Infof("starting prometheus http")

	//http.Handle("/metrics", promhttp.Handler())
	//go func() {
	//	http.ListenAndServe(":9091", nil)
	//}()
}
