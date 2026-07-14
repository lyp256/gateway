package controller

import (
	"net/http"
	"strings"

	"github.com/VictoriaMetrics/metrics"
)

const (
	metricsDnsQueryTotal          = "dns_query_total"
	metricsDnsUpsteamServers      = "dns_upsteam_servers"
	metricsBpfRouteTotal          = "bpf_route_total"
	metricsDnsQueryDurationSecond = "dns_query_dration_secound"
)

func (ctl *controller) metrics(w http.ResponseWriter, req *http.Request) {
	ctl.metricsSet.WritePrometheus(w)
	metrics.WriteGoMetrics(w)
	metrics.WriteProcMetrics(w)
	metrics.WriteFDMetrics(w)
}

func (ctl *controller) initMetrics() {
	ctl.metricsSet = metrics.NewSet()
	ctl.dnsQuerySucceed()
	ctl.dnsQueryFailed()
	ctl.metricsSet.NewGauge(metricsDnsUpsteamServers, func() float64 {
		return float64(len(ctl.dnsServers))
	})
	ctl.metricsSet.NewGauge(metricsBpfRouteTotal, func() float64 {
		return float64(ctl.routeTable.Size4())
	})
}

func (ctl *controller) _getConterMetrics(name string, labels ...string) *metrics.Counter {
	return ctl.metricsSet.GetOrCreateCounter(buildNmae(name, labels...))
}

func (ctl *controller) _getHistogramMetrics(name string, labels ...string) *metrics.PrometheusHistogram {
	return ctl.metricsSet.GetOrCreatePrometheusHistogram(buildNmae(name, labels...))
}

func (ctl *controller) dnsQuerySucceed() *metrics.Counter {
	return ctl._getConterMetrics(metricsDnsQueryTotal, "status", "succeed")
}

func (ctl *controller) dnsQueryFailed() *metrics.Counter {
	return ctl._getConterMetrics(metricsDnsQueryTotal, "status", "failed")
}

func (ctl *controller) dnsQuerySucceedDurationSecond() *metrics.PrometheusHistogram {
	return ctl._getHistogramMetrics(metricsDnsQueryDurationSecond, "status", "succeed")
}

func (ctl *controller) dnsQueryFailedDurationSecond() *metrics.PrometheusHistogram {
	return ctl._getHistogramMetrics(metricsDnsQueryDurationSecond, "status", "failed")
}

func buildNmae(name string, labels ...string) string {
	if len(labels)%2 != 0 {
		panic("invalid metrics labels")
	}
	n := len(name) + 2 + len(labels)*3/2
	for _, label := range labels {
		n += len(label)
	}
	b := strings.Builder{}
	b.Grow(n)
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(labels[i+1])
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	return b.String()
}
