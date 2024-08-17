package f2b

import (
	"github.com/prometheus/client_golang/prometheus"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/socket"
	"log"
	"strconv"
)

const (
	namespace = "f2b"
)

var (
	metricErrorCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "errors"),
		"Number of errors found since startup",
		[]string{"type"}, nil,
	)
	metricServerUp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Check if the fail2ban server is up",
		nil, nil,
	)
	metricJailCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_count"),
		"Number of defined jails",
		nil, nil,
	)
	metricJailFailedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_current"),
		"Number of current failures on this jail's filter",
		[]string{"jail"}, nil,
	)
	metricJailFailedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_total"),
		"Number of total failures on this jail's filter",
		[]string{"jail"}, nil,
	)
	metricJailBannedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_current"),
		"Number of IPs currently banned in this jail",
		[]string{"jail"}, nil,
	)
	metricJailBannedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_total"),
		"Total number of IPs banned by this jail (includes expired bans)",
		[]string{"jail"}, nil,
	)
	metricJailBanTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_ban_time"),
		"How long an IP is banned for in this jail (in seconds)",
		[]string{"jail"}, nil,
	)
	metricJailFindTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_find_time"),
		"How far back will the filter look for failures in this jail (in seconds)",
		[]string{"jail"}, nil,
	)
	metricJailMaxRetry = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_max_retries"),
		"The number of failures allowed until the IP is banned by this jail",
		[]string{"jail"}, nil,
	)
	metricVersionInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "version"),
		"Version of the exporter and fail2ban server",
		[]string{"exporter", "fail2ban"}, nil,
	)
	metricBannedGeo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "banned_ip_per_geo"),
		"Number of IP banned per geo location",
		[]string{"country", "city", "latitude", "longitude"}, nil,
	)
)

func (c *Collector) collectErrorCountMetric(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(c.socketConnectionErrorCount), "socket_conn",
	)
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(c.socketRequestErrorCount), "socket_req",
	)
}

func (c *Collector) collectServerUpMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	var serverUp float64 = 0
	if s != nil {
		pingSuccess, err := s.Ping()
		if err != nil {
			c.socketRequestErrorCount++
			log.Print(err)
		}
		if err == nil && pingSuccess {
			serverUp = 1
		}
	}
	ch <- prometheus.MustNewConstMetric(
		metricServerUp, prometheus.GaugeValue, serverUp,
	)
}

func (c *Collector) collectJailMetrics(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	jails, err := s.GetJails()
	var count float64 = 0
	if err != nil {
		c.socketRequestErrorCount++
		log.Print(err)
	}
	if err == nil {
		count = float64(len(jails))
	}
	ch <- prometheus.MustNewConstMetric(
		metricJailCount, prometheus.GaugeValue, count,
	)

	for i := range jails {
		c.collectJailStatsMetric(ch, s, jails[i])
		c.collectJailConfigMetrics(ch, s, jails[i])
	}
}

func (c *Collector) collectJailStatsMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket, jail string) {
	stats, err := s.GetJailStats(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get stats for jail %s: %v", jail, err)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		metricJailFailedCurrent, prometheus.GaugeValue, float64(stats.FailedCurrent), jail,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailFailedTotal, prometheus.GaugeValue, float64(stats.FailedTotal), jail,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailBannedCurrent, prometheus.GaugeValue, float64(stats.BannedCurrent), jail,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailBannedTotal, prometheus.GaugeValue, float64(stats.BannedTotal), jail,
	)
}

func (c *Collector) collectJailConfigMetrics(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket, jail string) {
	banTime, err := s.GetJailBanTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get ban time for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailBanTime, prometheus.GaugeValue, float64(banTime), jail,
		)
	}
	findTime, err := s.GetJailFindTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get find time for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailFindTime, prometheus.GaugeValue, float64(findTime), jail,
		)
	}
	maxRetry, err := s.GetJailMaxRetries(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get max retries for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailMaxRetry, prometheus.GaugeValue, float64(maxRetry), jail,
		)
	}
}

func (c *Collector) collectVersionMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	fail2banVersion, err := s.GetServerVersion()
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get fail2ban server version: %v", err)
	}

	ch <- prometheus.MustNewConstMetric(
		metricVersionInfo, prometheus.GaugeValue, float64(1), c.exporterVersion, fail2banVersion,
	)
}

func (c *Collector) collectBannedMetrics(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {

	if c.GeoIpApiUrl == "" {
		return
	}

	bans, err := s.GetBanned(c.GeoIpApiUrl)
	if err != nil {
		c.socketRequestErrorCount++
		log.Print(err)
	}
	if err == nil {
		for _, ban := range bans {
			ch <- prometheus.MustNewConstMetric(
				metricBannedGeo, prometheus.GaugeValue, float64(ban.Count), ban.CountryCode, ban.CityName, strconv.FormatFloat(ban.Lat, 'f', -1, 64), strconv.FormatFloat(ban.Lon, 'f', -1, 64),
			)
		}
	}
}
