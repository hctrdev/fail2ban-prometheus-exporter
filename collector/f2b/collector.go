package f2b

import (
	"github.com/prometheus/client_golang/prometheus"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/cfg"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/socket"
	"log"
	"os"
)

type Collector struct {
	socketPath                 string
	exporterVersion            string
	lastError                  error
	socketConnectionErrorCount int
	socketRequestErrorCount    int
	exitOnSocketConnError      bool
}

func NewExporter(appSettings *cfg.AppSettings, exporterVersion string) *Collector {
	log.Printf("reading metrics from fail2ban socket: %s", appSettings.Fail2BanSocketPath)
	return &Collector{
		socketPath:                 appSettings.Fail2BanSocketPath,
		exporterVersion:            exporterVersion,
		lastError:                  nil,
		socketConnectionErrorCount: 0,
		socketRequestErrorCount:    0,
		exitOnSocketConnError:      appSettings.ExitOnSocketConnError,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricServerUp
	ch <- metricJailCount
	ch <- metricJailFailedCurrent
	ch <- metricJailFailedTotal
	ch <- metricJailBannedCurrent
	ch <- metricJailBannedTotal
	ch <- metricErrorCount
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		if c.exitOnSocketConnError {
			os.Exit(1)
		}
	} else {
		defer s.Close()
	}

	c.collectServerUpMetric(ch, s)
	if err == nil && s != nil {
		c.collectJailMetrics(ch, s)
		c.collectVersionMetric(ch, s)
	}
	c.collectErrorCountMetric(ch)
}
