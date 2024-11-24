package f2b

import (
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/cfg"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/socket"
)

type Collector struct {
	socketPath                 string
	exporterVersion            string
	lastError                  error
	socketConnectionErrorCount int
	socketRequestErrorCount    int
	exitOnSocketConnError      bool
	GeoIpApiUrl                string
}

func NewExporter(appSettings *cfg.AppSettings, exporterVersion string) *Collector {
	log.Printf("reading fail2ban metrics from socket file: %s", appSettings.Fail2BanSocketPath)
	printFail2BanServerVersion(appSettings.Fail2BanSocketPath)
	return &Collector{
		socketPath:                 appSettings.Fail2BanSocketPath,
		exporterVersion:            exporterVersion,
		lastError:                  nil,
		socketConnectionErrorCount: 0,
		socketRequestErrorCount:    0,
		exitOnSocketConnError:      appSettings.ExitOnSocketConnError,
		GeoIpApiUrl:                appSettings.GeoIpApiUrl,
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
	ch <- metricBannedGeo
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
		c.collectBannedMetrics(ch, s)
		c.collectVersionMetric(ch, s)
	}
	c.collectErrorCountMetric(ch)
}

func (c *Collector) IsHealthy() bool {
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		return false
	}
	pingSuccess, err := s.Ping()
	if err != nil {
		log.Printf("error pinging fail2ban server: %v", err)
		c.socketRequestErrorCount++
		return false
	}
	return pingSuccess
}

func printFail2BanServerVersion(socketPath string) {
	s, err := socket.ConnectToSocket(socketPath)
	if err != nil {
		log.Printf("error connecting to socket: %v", err)
	} else {
		version, err := s.GetServerVersion()
		if err != nil {
			log.Printf("error interacting with socket: %v", err)
		} else {
			log.Printf("successfully connected to fail2ban socket! fail2ban version: %s", version)
		}
	}
}
