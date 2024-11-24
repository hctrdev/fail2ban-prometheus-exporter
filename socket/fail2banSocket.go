package socket

import (
	"fmt"
	"github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/types"
	"net"
	"net/http"
	"net/url"
	"strings"
	"slices"
	"maps"
	"encoding/json"
	"io/ioutil"
)

type Fail2BanSocket struct {
	socket  net.Conn
	encoder *ogórek.Encoder
}

type JailStats struct {
	FailedCurrent int
	FailedTotal   int
	BannedCurrent int
	BannedTotal   int
}

type GeoIP struct {
	IP          string  `json:"Ip"`
	Network     string  `json:"Network"`
	GeoID       int     `json:"GeoId"`
	CountryCode string  `json:"CountryCode"`
	CountryName string  `json:"CountryName"`
	CityName    string  `json:"CityName"`
	Lat         float64 `json:"Lat"`
	Lon         float64 `json:"Lon"`
	Count       int
}

type GeoIPList struct {
	City []GeoIP `json:"city"`
}

func ConnectToSocket(path string) (*Fail2BanSocket, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Fail2BanSocket{
		socket:  c,
		encoder: ogórek.NewEncoder(c),
	}, nil
}

func (s *Fail2BanSocket) Close() error {
	return s.socket.Close()
}

func (s *Fail2BanSocket) Ping() (bool, error) {
	response, err := s.sendCommand([]string{pingCommand, "100"})
	if err != nil {
		return false, newConnectionError(pingCommand, err)
	}

	if t, ok := response.(*types.Tuple); ok {
		if (*t)[1] == "pong" {
			return true, nil
		}
		return false, fmt.Errorf("unexpected response data (expecting 'pong'): %s", (*t)[1])
	}
	return false, newBadFormatError(pingCommand, response)
}

func (s *Fail2BanSocket) GetJails() ([]string, error) {
	response, err := s.sendCommand([]string{statusCommand})
	if err != nil {
		return nil, err
	}

	if lvl1, ok := response.(*types.Tuple); ok {
		if lvl2, ok := lvl1.Get(1).(*types.List); ok {
			if lvl3, ok := lvl2.Get(1).(*types.Tuple); ok {
				if lvl4, ok := lvl3.Get(1).(string); ok {
					splitJails := strings.Split(lvl4, ",")
					return trimSpaceForAll(splitJails), nil
				}
			}
		}
	}
	return nil, newBadFormatError(statusCommand, response)
}

func (s *Fail2BanSocket) GetJailStats(jail string) (JailStats, error) {
	response, err := s.sendCommand([]string{statusCommand, jail})
	if err != nil {
		return JailStats{}, err
	}

	stats := JailStats{
		FailedCurrent: -1,
		FailedTotal:   -1,
		BannedCurrent: -1,
		BannedTotal:   -1,
	}

	if lvl1, ok := response.(*types.Tuple); ok {
		if lvl2, ok := lvl1.Get(1).(*types.List); ok {
			if filter, ok := lvl2.Get(0).(*types.Tuple); ok {
				if filterLvl1, ok := filter.Get(1).(*types.List); ok {
					if filterCurrentTuple, ok := filterLvl1.Get(0).(*types.Tuple); ok {
						if filterCurrent, ok := filterCurrentTuple.Get(1).(int); ok {
							stats.FailedCurrent = filterCurrent
						}
					}
					if filterTotalTuple, ok := filterLvl1.Get(1).(*types.Tuple); ok {
						if filterTotal, ok := filterTotalTuple.Get(1).(int); ok {
							stats.FailedTotal = filterTotal
						}
					}
				}
			}
			if actions, ok := lvl2.Get(1).(*types.Tuple); ok {
				if actionsLvl1, ok := actions.Get(1).(*types.List); ok {
					if actionsCurrentTuple, ok := actionsLvl1.Get(0).(*types.Tuple); ok {
						if actionsCurrent, ok := actionsCurrentTuple.Get(1).(int); ok {
							stats.BannedCurrent = actionsCurrent
						}
					}
					if actionsTotalTuple, ok := actionsLvl1.Get(1).(*types.Tuple); ok {
						if actionsTotal, ok := actionsTotalTuple.Get(1).(int); ok {
							stats.BannedTotal = actionsTotal
						}
					}
				}
			}
			return stats, nil
		}
	}
	return stats, newBadFormatError(statusCommand, response)
}

func (s *Fail2BanSocket) GetJailBanTime(jail string) (int, error) {
	command := fmt.Sprintf(banTimeCommandFmt, jail)
	return s.sendSimpleIntCommand(command)
}

func (s *Fail2BanSocket) GetJailFindTime(jail string) (int, error) {
	command := fmt.Sprintf(findTimeCommandFmt, jail)
	return s.sendSimpleIntCommand(command)
}

func (s *Fail2BanSocket) GetJailMaxRetries(jail string) (int, error) {
	command := fmt.Sprintf(maxRetriesCommandFmt, jail)
	return s.sendSimpleIntCommand(command)
}

func (s *Fail2BanSocket) GetServerVersion() (string, error) {
	response, err := s.sendCommand([]string{versionCommand})
	if err != nil {
		return "", err
	}

	if lvl1, ok := response.(*types.Tuple); ok {
		if versionStr, ok := lvl1.Get(1).(string); ok {
			return versionStr, nil
		}
	}
	return "", newBadFormatError(versionCommand, response)
}

// sendSimpleIntCommand sends a command to the fail2ban socket and parses the response to extract an int.
// This command assumes that the response data is in the format of `(d, d)` where `d` is a number.
func (s *Fail2BanSocket) sendSimpleIntCommand(command string) (int, error) {
	response, err := s.sendCommand(strings.Split(command, " "))
	if err != nil {
		return -1, err
	}

	if lvl1, ok := response.(*types.Tuple); ok {
		if banTime, ok := lvl1.Get(1).(int); ok {
			return banTime, nil
		}
	}
	return -1, newBadFormatError(command, response)
}

func newBadFormatError(command string, data interface{}) error {
	return fmt.Errorf("(%s) unexpected response format - cannot parse: %v", command, data)
}

func newConnectionError(command string, err error) error {
	return fmt.Errorf("(%s) failed to send command through socket: %v", command, err)
}

func trimSpaceForAll(slice []string) []string {
	for i := range slice {
		slice[i] = strings.TrimSpace(slice[i])
	}
	return slice
}

/* banned command returns the following structure :
 *  [
 *    {
 *      'jail1': [
 *        'ip11',
 *        '...',
 *        'ip1N'
 *      ]
 *    }, {
 *      ...
 *    }, {
 *      'jailN': [
 *        'ipN1',
 *        '...',
 *        'ipNN'
 *      ]
 *    }
 *  ]
*/
func (s *Fail2BanSocket) GetBanned(GeoIpApiUrl string) ([]*GeoIP, error) {
	response, err := s.sendCommand([]string{bannedCommand})
	if err != nil {
		return nil, err
	}

	var (
		ips    map[string]bool  // A temporary map to store a list of unique IPs
		geos   map[int]*GeoIP   // A temporary map to store a list of unique locations
		result []*GeoIP
	)

	ips = make(map[string]bool)
	geos = make(map[int]*GeoIP)

	// Response is a Tuple (status, data)
	if lvl1, ok := response.(*types.Tuple); ok {
		// Get list of jails
		if lvl2, ok := lvl1.Get(1).(*types.List); ok {
			// Iterate over each jail
			for jail := 0; jail < lvl2.Len(); jail++ {
				// Get dict of current jail
				if lvl3, ok := lvl2.Get(jail).(*types.Dict); ok {
					// Dict contains a single key which is the jail name
					jail_name := lvl3.Keys()[0]
					// Get list of IPs banned for current jail
					if lvl4, ok := lvl3.Get(jail_name); ok {
						if lvl5, ok := lvl4.(*types.List); ok {
							// Iterate over each IP and store them in the temporary IP map for dedupe
							for i := 0; i < lvl5.Len(); i++ {
								ips[lvl5.Get(i).(string)] = true
							}
						}
					}
				}
			}

			// Join all IPs into a single string with comma as separator and call the GeoIP server API
			var reshttp *http.Response
			ips2 := slices.Collect(maps.Keys(ips))
			reshttp, err = http.PostForm(GeoIpApiUrl, url.Values{"ips": {strings.Join(ips2[:], ",")}})
			if err != nil {
				fmt.Println(err)
				return nil, newBadFormatError(bannedCommand, response)
			}
			defer reshttp.Body.Close()

			// Read returned body
			var body []byte
			body, err = ioutil.ReadAll(reshttp.Body)
			if err != nil {
				fmt.Println(err)
				return nil, newBadFormatError(bannedCommand, response)
			}

			// Map received JSON data to internal structure
			var geolist GeoIPList
			err = json.Unmarshal(body, &geolist)
			if err != nil {
				fmt.Println(err)
				return nil, newBadFormatError(bannedCommand, response)
			}

			if len(geolist.City) > 0 {
				// Iterate over each Geo result
				for i, _ := range geolist.City {
					var geoip GeoIP
					geoip = geolist.City[i]
					geoip.Count = 0

					// If this GeoID has not be seen yet, we add it to the result
					if _, ok := geos[geoip.GeoID]; !ok {
							geos[geoip.GeoID] = &geoip
					}

					// Increment the counter for this GeoID
					geos[geoip.GeoID].Count++
				}

				// Transpose the temporary Geo map to a final Geo list
				for geoid := range geos {
					result = append(result, geos[geoid])
				}

				return result, nil
			}
		}
	}

	return nil, newBadFormatError(bannedCommand, response)
}
