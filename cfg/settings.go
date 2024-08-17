package cfg

import "gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/auth"

type AppSettings struct {
	VersionMode           bool
	DryRunMode            bool
	MetricsAddress        string
	Fail2BanSocketPath    string
	FileCollectorPath     string
	AuthProvider          auth.AuthProvider
	ExitOnSocketConnError bool
	GeoIpApiUrl           string
}
