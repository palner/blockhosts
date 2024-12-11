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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"

	"github.com/coreos/go-iptables/iptables"
)

type Re map[string]*regexp.Regexp

var (
	APIport     string
	logFile     string
	chainName   string
	targetChain string
	sshLog      string
)

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

	ips, err := SshAuthCheck(sshLog)
	if err != nil {
		log.Println("error accessing log:", err)
		runtime.Goexit()
	}

	if ips == nil {
		log.Println("no ips found")
		runtime.Goexit()
	}

	log.Println("ips found. blocking ips with 3 or more attempts")
	freq := make(map[string]int)
	for _, ip := range ips {
		freq[string(ip)] = freq[string(ip)] + 1
	}

	for address, count := range freq {
		if count > 2 {
			log.Println("blocking", address, "with count of", count)
			iptableHandle("ipv4", "add", address)
		} else {
			log.Println("not blocking", address, "with count of", count)
		}
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

func SshAuthCheck(logfile string) ([]string, error) {
	var addresses []string
	file, err := os.Open(logfile)
	if err != nil {
		return addresses, err
	}

	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return addresses, fmt.Errorf("failed to read file %s: %v\n", logfile, err)
		}

		// parse Uid=<num>
		re := regexp.MustCompile(`Connection closed by\D+([0-9]{0,3}\.){3}[0-9]{0,3}`)
		re2 := regexp.MustCompile(`([0-9]{0,3}\.){3}[0-9]{0,3}`)
		token := re.FindString(string(line))
		if token == "" {
			continue
		} else {
			token2 := re2.FindString(token)
			if token2 == "" {
				continue
			} else {
				addresses = append(addresses, token2)
			}
		}
	}

	return addresses, nil
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
