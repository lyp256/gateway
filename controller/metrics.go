package controller

import (
	"net/http"

	"github.com/VictoriaMetrics/metrics"
)

func (ctl *controller) metrics(w http.ResponseWriter, req *http.Request) {
	ctl.metricsSet.WritePrometheus(w)
	metrics.WriteGoMetrics(w)
	metrics.WriteProcMetrics(w)
	metrics.WriteFDMetrics(w)
}

func (ctl *controller) initMetrics() {
	ctl.metricsSet = metrics.NewSet()
	ctl.dnsQueryTotal = ctl.metricsSet.NewCounter("dns_query_total")
	ctl.dnsQuerySucceed = ctl.metricsSet.NewCounter("dns_query_succeed")
	ctl.dnsQueryFailed = ctl.metricsSet.NewCounter("dns_query_failed")
	ctl.metricsSet.NewGauge("dns_upsteam_servers", func() float64 {
		return float64(len(ctl.dnsServers))
	})
	ctl.metricsSet.NewGauge("bpf_route_total", func() float64 {
		return float64(ctl.routeTable.Size4())
	})

}
