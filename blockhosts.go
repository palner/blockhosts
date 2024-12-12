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

GOOS=linux GOARCH=amd64 go build -o blockhosts
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o blockhosts
GOOS=linux GOARCH=arm GOARM=7 go build -o blockhosts-pi

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

	"github.com/coreos/go-iptables/iptables"
)

type Re map[string]*regexp.Regexp

var (
	APIport     string
	logFile     string
	chainName   string
	targetChain string
	sshLog      string
	bhc         *BHconfig
)

type BHconfig struct {
	LastLineRead int `json:"last_line,omitempty"`
	IpList       []IPAddresses
	sourceFile   string
}

type IPAddresses struct {
	Ip    string `json:"ip"`
	Count int    `json:"count"`
}

func init() {
	flag.StringVar(&targetChain, "target", "DROP", "target chain for matching entries")
	flag.StringVar(&chainName, "chain", "APIBANLOCAL", "chain name for entries")
	flag.StringVar(&logFile, "log", "/var/log/blockhosts.log", "location of log file or - for stdout")
	flag.StringVar(&sshLog, "ssh", "/var/log/auth.log", "location of ssh log")

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

	log.Println("current ip count:")
	PrintIPCount(bhc.IpList)

	var ips []string
	ips, bhc.LastLineRead, err = SshAuthCheck(sshLog)
	if err != nil {
		log.Println("error accessing log:", err)
		runtime.Goexit()
	}

	if ips == nil {
		log.Println("no new ips found. lines read:", bhc.LastLineRead)
		if err := bhc.Update(); err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}

	for _, t := range bhc.IpList {
		ipaddress := t.Ip
		count := t.Count

		for i := 0; i <= count; i++ {
			ips = append(ips, ipaddress)
		}
	}

	log.Println("ips found. blocking ips with 3 or more attempts")
	freq := make(map[string]int)
	for _, ip := range ips {
		freq[string(ip)] = freq[string(ip)] + 1
	}

	var updatedLlist []IPAddresses
	for address, count := range freq {
		parseList := IPAddresses{
			Ip:    address,
			Count: count,
		}

		updatedLlist = append(updatedLlist, parseList)
		if count > 2 {
			log.Println("blocking", address, "with count of", count)
			iptableHandle("ipv4", "add", address)
		} else {
			log.Println("not blocking", address, "with count of", count)
		}
	}

	log.Println("updated count:")
	bhc.IpList = updatedLlist
	PrintIPCount(bhc.IpList)
	if err := bhc.Update(); err != nil {
		log.Fatal(err)
	}
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

// Function to see if string within string
func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func initializeIPTables(ipt *iptables.IPTables) (string, error) {
	// Get existing chains from IPTABLES
	originaListChain, err := ipt.ListChains("filter")
	if err != nil {
		return "error", fmt.Errorf("failed to read iptables: %w", err)
	}

	// Search for INPUT in IPTABLES
	chain := "INPUT"
	if !contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected INPUT chain")
	}

	// Search for FORWARD in IPTABLES
	chain = "FORWARD"
	if !contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected FORWARD chain")
	}

	// Search for chainName in IPTABLES
	if contains(originaListChain, chainName) {
		// chainName already exists
		return "chain exists", nil
	}

	log.Print("IPTABLES doesn't contain " + chainName + ". Creating now...")

	// Add chain
	err = ipt.ClearChain("filter", chainName)
	if err != nil {
		return "error", fmt.Errorf("failed to clear chain: %w", err)
	}

	// Add chainName to INPUT
	err = ipt.Insert("filter", "INPUT", 1, "-j", chainName)
	if err != nil {
		return "error", fmt.Errorf("failed to add chain to INPUT chain: %w", err)
	}

	// Add chain to FORWARD
	err = ipt.Insert("filter", "FORWARD", 1, "-j", chainName)
	if err != nil {
		return "error", fmt.Errorf("failed to add chain to FORWARD chain: %w", err)
	}

	return chainName + " created", nil
}

func SshAuthCheck(logfile string) ([]string, int, error) {
	var addresses []string
	var matchRules []string
	matchRules = append(matchRules, `Connection closed by\D+([0-9]{0,3}\.){3}[0-9]{0,3}`)
	matchRules = append(matchRules, `Received disconnect from\D+([0-9]{0,3}\.){3}[0-9]{0,3}(.*)\:\s\s\[preauth\]`)
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
			log.Println("reading line", linecount)
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

func iptableHandle(proto string, task string, ipvar string) (string, error) {
	log.Println("iptableHandle:", proto, task, ipvar)

	var ipProto iptables.Protocol
	switch proto {
	case "ipv6":
		ipProto = iptables.ProtocolIPv6
	default:
		ipProto = iptables.ProtocolIPv4
	}

	// Go connect for IPTABLES
	ipt, err := iptables.NewWithProtocol(ipProto)
	if err != nil {
		log.Println("iptableHandle:", err)
		return "", err
	}

	_, err = initializeIPTables(ipt)
	if err != nil {
		log.Fatalln("iptableHandler: failed to initialize IPTables:", err)
		return "", err
	}

	switch task {
	case "add":
		err = ipt.AppendUnique("filter", chainName, "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error adding address", err)
			return "", err
		} else {
			return "added", nil
		}
	case "delete":
		err = ipt.DeleteIfExists("filter", chainName, "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error removing address", err)
			return "", err
		} else {
			return "deleted", nil
		}
	case "flush":
		err = ipt.ClearChain("filter", chainName)
		if err != nil {
			log.Println("iptableHandler:", proto, err)
			return "", err
		} else {
			return "flushed", nil
		}
	case "push":
		var exists = false
		exists, err = ipt.Exists("filter", chainName, "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error checking if ip already exists", err)
			return "error checking if ip already exists in the chain", err
		} else {
			if exists {
				err = errors.New("ip already exists")
				log.Println("iptableHandler: ip already exists", err)
				return "ip already exists", err
			} else {
				err = ipt.Insert("filter", chainName, 1, "-s", ipvar, "-d", "0/0", "-j", targetChain)
				if err != nil {
					log.Println("iptableHandler: error pushing address", err)
					return "", err
				} else {
					return "pushed", nil
				}
			}
		}
	default:
		log.Println("iptableHandler: unknown task")
		return "", errors.New("unknown task")
	}
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
		"/etc/blockhosts/"+fileName,
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

func PrintIPCount(ips []IPAddresses) {
	log.Println("---------")
	for ip, count := range ips {
		log.Println(ip, ":", count)
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
