package cfg

import (
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kong"
	"gitlab.com/hectorjsmith/fail2ban-prometheus-exporter/auth"
)

var cliStruct struct {
	VersionMode          bool   `name:"version" short:"v" help:"Show version info and exit"`
	DryRunMode           bool   `name:"dry-run" help:"Attempt to connect to the fail2ban socket then exit before starting the server"`
	ServerAddress        string `name:"web.listen-address" env:"F2B_WEB_LISTEN_ADDRESS" help:"Address to use for the metrics server" default:"${default_address}"`
	F2bSocketPath        string `name:"collector.f2b.socket" env:"F2B_COLLECTOR_SOCKET" help:"Path to the fail2ban server socket" default:"${default_socket}"`
	ExitOnSocketError    bool   `name:"collector.f2b.exit-on-socket-connection-error" env:"F2B_EXIT_ON_SOCKET_CONN_ERROR" help:"When set to true the exporter will immediately exit on a fail2ban socket connection error"`
	GeoIpApiUrl          string `name:"collector.geoip-api.url" env:"F2B_COLLECTOR_GEOIP_API_URL" help:"URL to GeoIP API server"`
	TextFileExporterPath string `name:"collector.textfile.directory" env:"F2B_COLLECTOR_TEXT_PATH" help:"Directory to read text files with metrics from"`
	BasicAuthUser        string `name:"web.basic-auth.username" env:"F2B_WEB_BASICAUTH_USER" help:"Username to use to protect endpoints with basic auth"`
	BasicAuthPass        string `name:"web.basic-auth.password" env:"F2B_WEB_BASICAUTH_PASS" help:"Password to use to protect endpoints with basic auth"`
}

func Parse() *AppSettings {
	ctx := kong.Parse(
		&cliStruct,
		kong.Vars{
			"default_socket":  "/var/run/fail2ban/fail2ban.sock",
			"default_address": ":9191",
		},
		kong.Name("fail2ban_exporter"),
		kong.Description("🚀 Export prometheus metrics from a running Fail2Ban instance"),
		kong.UsageOnError(),
	)

	validateFlags(ctx)
	settings := &AppSettings{
		VersionMode:           cliStruct.VersionMode,
		DryRunMode:            cliStruct.DryRunMode,
		MetricsAddress:        cliStruct.ServerAddress,
		Fail2BanSocketPath:    cliStruct.F2bSocketPath,
		FileCollectorPath:     cliStruct.TextFileExporterPath,
		ExitOnSocketConnError: cliStruct.ExitOnSocketError,
		GeoIpApiUrl:           cliStruct.GeoIpApiUrl,
		AuthProvider:          createAuthProvider(),
	}
	return settings
}

func createAuthProvider() auth.AuthProvider {
	username := cliStruct.BasicAuthUser
	password := cliStruct.BasicAuthPass

	if len(username) == 0 && len(password) == 0 {
		return auth.NewEmptyAuthProvider()
	}
	log.Print("basic auth enabled")
	return auth.NewBasicAuthProvider(username, password)
}

func validateFlags(cliCtx *kong.Context) {
	var flagsValid = true
	var messages = []string{}
	if !cliStruct.VersionMode {
		if cliStruct.F2bSocketPath == "" {
			messages = append(messages, "error: fail2ban socket path must not be blank")
			flagsValid = false
		}
		if cliStruct.ServerAddress == "" {
			messages = append(messages, "error: invalid server address, must not be blank")
			flagsValid = false
		}
		if (len(cliStruct.BasicAuthUser) > 0) != (len(cliStruct.BasicAuthPass) > 0) {
			messages = append(messages, "error: to enable basic auth both the username and the password must be provided")
			flagsValid = false
		}
	}
	if !flagsValid {
		cliCtx.PrintUsage(false)
		fmt.Println()
		for i := 0; i < len(messages); i++ {
			fmt.Println(messages[i])
		}
		os.Exit(1)
	}
}
