/*

MIT License

Copyright (c) 2024 Fred Posner
Copyright (c) 2024 The Palner Group, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Building:

GOOS=linux GOARCH=amd64 go build -o binary/blockhosts
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o binary/blockhosts
GOOS=linux GOARCH=arm GOARM=7 go build -o binary/blockhosts-pi

*/

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"

	"blockhosts/bhipt"
)

type Re map[string]*regexp.Regexp

var (
	APIport     string
	logFile     string
	chainName   string
	targetChain string
	sshLog      string
	extraLog    bool
	bhc         *BHconfig
)

type BHconfig struct {
	LastLineRead int `json:"last_line,omitempty"`
	Allowed      []IPNet
	Blocked      []IPAddressesTime
	Watching     []IPAddressesCountTime
	sourceFile   string
}

type IPAddressesCount struct {
	Ip    string `json:"ip"`
	Count int    `json:"count"`
}

type IPAddressesCountTime struct {
	Ip        string `json:"ip"`
	Count     int    `json:"count"`
	TimeStamp int64  `json:"timestamp"`
}

type IPAddresses struct {
	Ip string `json:"ip"`
}

type IPAddressesTime struct {
	Ip        string `json:"ip"`
	TimeStamp int64  `json:"timestamp"`
}

type IPNet struct {
	Cidr string `json:"cidr"`
}

func init() {
	flag.StringVar(&targetChain, "target", "DROP", "target chain for matching entries")
	flag.StringVar(&chainName, "chain", "APIBANLOCAL", "chain name for entries")
	flag.StringVar(&logFile, "log", "/var/log/blockhosts.log", "location of log file or - for stdout")
	flag.StringVar(&sshLog, "ssh", "/var/log/auth.log", "location of ssh log")
	flag.BoolVar(&extraLog, "xtra", false, "log extra")

}

func main() {
	defer os.Exit(0)
	flag.Parse()
	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}

		defer lf.Close()
		log.SetFlags(log.LstdFlags)
		log.SetOutput(lf)
	}

	log.Println("-> [o] Loading config")
	bhconfig, err := LoadConfig()
	if err != nil {
		log.Println("-> [X] config error:", err.Error())
		panic(err.Error())
	} else {
		bhc = bhconfig
	}

	if bhc.LastLineRead > 0 {
		log.Println("last line read:", bhc.LastLineRead)
	} else {
		log.Println("unknown last line:", bhc.LastLineRead)
		bhc.LastLineRead = 0
		log.Println("last line now:", bhc.LastLineRead)
	}

	if extraLog {
		log.Println("current ip count:")
		PrintIPCount(bhc.Watching)
	}

	// get current blocked
	nowTimeStamp := bhipt.GetTime()
	var newBlockList []IPAddressesTime
	blocked, _ := bhipt.GetIPaddressesFromChainIPv4(chainName)
	if blocked == nil {
		log.Println("nothing blocked in", chainName, "checking config")
		if bhc.Blocked == nil {
			log.Println("no blocks listed in cfg either")
		} else {
			log.Println("sync cfg blocks to iptables")
			for _, v := range bhc.Blocked {
				if !bhipt.BeenAWeek(v.TimeStamp) {
					bhipt.IptableHandle("ipv4", "add", v.Ip, extraLog, chainName, targetChain)
					if !ContainsIPAddressesTime(newBlockList, v.Ip) {
						tempBlocked := IPAddressesTime{
							Ip:        v.Ip,
							TimeStamp: v.TimeStamp,
						}

						newBlockList = append(newBlockList, tempBlocked)
						blocked = append(blocked, v.Ip)
					}
				} else {
					log.Println("not blocking", v.Ip, "- too old")
				}
			}
		}
	} else {
		if extraLog {
			log.Println(blocked)
		}

		if bhc.Blocked == nil {
			log.Println("config blocklist is nil, but there are blocks in IPTABLES")
			for _, ipvalue := range blocked {
				if !ContainsIPAddressesTime(newBlockList, ipvalue) {
					tempBlocked := IPAddressesTime{
						Ip:        ipvalue,
						TimeStamp: nowTimeStamp,
					}

					newBlockList = append(newBlockList, tempBlocked)
				}
			}
		} else {
			log.Println("check for old blocks")
			for _, v := range bhc.Blocked {
				if bhipt.BeenAWeek(v.TimeStamp) {
					if bhipt.Contains(blocked, v.Ip) {
						log.Println("removing week old ip", v.Ip, "from iptables")
						bhipt.IptableHandle("ipv4", "delete", v.Ip, extraLog, chainName, targetChain)
					}
				} else {
					if !ContainsIPAddressesTime(newBlockList, v.Ip) {
						tempBlocked := IPAddressesTime{
							Ip:        v.Ip,
							TimeStamp: v.TimeStamp,
						}

						newBlockList = append(newBlockList, tempBlocked)
					}
				}
			}
		}
	}

	for idx, val := range bhc.Watching {
		if bhipt.BeenAWeek(val.TimeStamp) {
			log.Println("removing", val.Ip, "from watchlist -- been a week")
			bhc.Watching = append(bhc.Watching[:idx], bhc.Watching[idx+1:]...)
		}
	}

	var ips []string
	ips, bhc.LastLineRead, err = SshAuthCheck(sshLog)
	if err != nil {
		log.Println("error accessing log:", err)
		runtime.Goexit()
	}

	if ips == nil {
		log.Println("no new ips found. lines read:", bhc.LastLineRead)
		bhc.Blocked = updateBlocklist(newBlockList)
		if err := bhc.Update(); err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}

	log.Println("ips found. blocking ips with 3 or more attempts")
	freq := make(map[string]int)
	for _, ip := range ips {
		freq[string(ip)] = freq[string(ip)] + 1
	}

	blockedcount := 0
	for address, count := range freq {
		if !ContainsIPAddressesCountTime(bhc.Watching, address) {
			parseList := IPAddressesCountTime{
				Ip:        address,
				Count:     count,
				TimeStamp: nowTimeStamp,
			}

			bhc.Watching = append(bhc.Watching, parseList)
		} else {
			for idx, val := range bhc.Watching {
				if val.Ip == address {
					newcount := val.Count + count
					bhc.Watching[idx].Count = newcount
					bhc.Watching[idx].TimeStamp = nowTimeStamp
				}
			}
		}
	}

	for _, val := range bhc.Watching {

		if val.Count > 2 {
			if extraLog {
				log.Println("blocking", val.Ip, "with count of", val.Count)
			}

			if bhipt.Contains(blocked, val.Ip) {
				if extraLog {
					log.Println(val.Ip, "already blocked")
				}
			} else {
				if bhc.Allowed == nil {
					bhipt.IptableHandle("ipv4", "add", val.Ip, extraLog, chainName, targetChain)
					if !ContainsIPAddressesTime(newBlockList, val.Ip) {

						addBlocked := IPAddressesTime{
							Ip:        val.Ip,
							TimeStamp: nowTimeStamp,
						}

						newBlockList = append(newBlockList, addBlocked)
						blockedcount++
					}
				} else {
					for _, v := range bhc.Allowed {
						if bhipt.ContainsIP(v.Cidr, val.Ip) {
							log.Println(val.Ip, "allowed in", v.Cidr, " - not blocking")
						} else {
							bhipt.IptableHandle("ipv4", "add", val.Ip, extraLog, chainName, targetChain)
							if !ContainsIPAddressesTime(newBlockList, val.Ip) {

								addBlocked := IPAddressesTime{
									Ip:        val.Ip,
									TimeStamp: nowTimeStamp,
								}

								newBlockList = append(newBlockList, addBlocked)
								blockedcount++
							}
						}
					}
				}
			}
		} else {
			if extraLog {
				log.Println("not blocking", val.Ip, "with count of", val.Count)
			}
		}
	}

	log.Println("blocking:", blockedcount, "addresses")

	bhc.Blocked = updateBlocklist(newBlockList)
	if extraLog {
		log.Println("updated blocklist")
		PrintIP(bhc.Blocked)
	}

	if extraLog {
		log.Println("updated watchlist")
		PrintIPCount(bhc.Watching)
	}

	if err := bhc.Update(); err != nil {
		log.Fatal(err)
	}

	log.Println("Done. New line marker:", bhc.LastLineRead)
}

func updateBlocklist(list []IPAddressesTime) []IPAddressesTime {
	var updatedBlocklist []IPAddressesTime
	for _, v := range list {
		parseList := IPAddressesTime{
			Ip:        v.Ip,
			TimeStamp: v.TimeStamp,
		}

		updatedBlocklist = append(updatedBlocklist, parseList)
	}

	return updatedBlocklist
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func SshAuthCheck(logfile string) ([]string, int, error) {
	var addresses []string
	var matchRules []string
	matchRules = append(matchRules, `Connection closed by\D+([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Received disconnect from\D+([0-9]{0,3}\.){3}[0-9]{0,3}(.*)\:\s\s\[preauth\]`)
	matchRules = append(matchRules, `Received disconnect from\D+([0-9]{0,3}\.){3}[0-9]{0,3}(.*)\[preauth\]`)
	matchRules = append(matchRules, `authentication failure(.*)rhost\=([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Failed password for(.*)([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Invalid user(.*)([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Disconnected from invalid\D+([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Disconnected from authenticating user\D+([0-9]{0,3}\.){3}[0-9]{0,3}(.*)\[preauth\]`)
	matchString := strings.Join(matchRules, "|")

	file, err := os.Open(logfile)
	if err != nil {
		log.Println("[ERR]", err.Error())
		return addresses, 0, err
	}

	defer file.Close()
	reader := bufio.NewReader(file)
	linecount := 0
	var read = false
	reader = bufio.NewReader(file)
	log.Println("parse log")
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			linecount++
			if !read {
				bhc.LastLineRead = 0
			}

			break
		} else if err != nil {
			return addresses, 0, fmt.Errorf("failed to read file %s: %v\n", logfile, err)
		}

		if linecount >= bhc.LastLineRead {
			read = true
			if extraLog {
				log.Println("reading line", linecount)
			}

			re := regexp.MustCompile(matchString)
			reip := regexp.MustCompile(`([0-9]{0,3}\.){3}[0-9]{0,3}`)
			token := re.FindString(string(line))
			if token != "" {
				ipaddress := reip.FindString(token)
				if ipaddress != "" {
					addresses = append(addresses, ipaddress)
				}
			}
		}

		linecount++
	}

	log.Println("done")
	return addresses, linecount, nil
}

// LoadConfig attempts to load the configuration file from various locations
func LoadConfig() (*BHconfig, error) {
	var fileLocations []string
	fileName := "bhconfig.json"

	// Add standard static locations
	fileLocations = append(fileLocations,
		fileName,
		"/usr/local/bin/"+fileName,
		"/etc/blockhosts/"+fileName,
		"/var/lib/blockhosts/"+fileName,
		"/usr/local/bin/blockhosts/"+fileName,
		"/usr/local/blockhosts/"+fileName,
	)

	for _, loc := range fileLocations {
		f, err := os.Open(loc)
		if err != nil {
			log.Println("-> [-] [LoadConfig] config not found in", loc)
			continue
		}

		log.Println("-> [-] [LoadConfig] trying config located in", loc)
		defer f.Close()
		cfg := new(BHconfig)
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
			log.Println("-> [x] [LoadConfig] error reading:", loc, err)
			return nil, fmt.Errorf("[LoadConfig] failed to read configuration from %s: %w", loc, err)
		}

		// Store the location of the config file so that we can update it later
		cfg.sourceFile = loc
		return cfg, nil
	}

	return nil, errors.New("[LoadConfig] failed to locate configuration file " + fileName)
}

func PrintIPCount(ips []IPAddressesCountTime) {
	log.Println("---------")
	for _, v := range ips {
		log.Println(v.Ip, ":", v.Count)
	}

	log.Println("---------")
}

func PrintIP(ips []IPAddressesTime) {
	log.Println("---------")
	for _, ip := range ips {
		log.Println(ip.Ip)
	}

	log.Println("---------")
}

func CountLines(r io.Reader) (int, error) {

	var count int
	var read int
	var err error
	var target []byte = []byte("\n")

	buffer := make([]byte, 32*1024)

	for {
		read, err = r.Read(buffer)
		if err != nil {
			break
		}

		count += bytes.Count(buffer[:read], target)
	}

	if err == io.EOF {
		return count, nil
	}

	return count, err
}

// Function to see if string within string
func ContainsIPAddressesTime(list []IPAddressesTime, value string) bool {
	for _, val := range list {
		if val.Ip == value {
			return true
		}
	}

	return false
}

func ContainsIPAddressesCountTime(list []IPAddressesCountTime, value string) bool {
	for _, val := range list {
		if val.Ip == value {
			return true
		}
	}

	return false
}

func (cfg *BHconfig) Update() error {
	f, err := os.Create(cfg.sourceFile)
	if err != nil {
		return fmt.Errorf("failed to open configuration file for writing: %w", err)
	}

	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	return enc.Encode(cfg)
}
