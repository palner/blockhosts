package bhipt

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

func AddIP(list []string, value string) []string {
	if value == "0.0.0.0" {
		return list
	}

	if Contains(list, value) {
		return list
	}

	list = append(list, value)
	return list
}

func BeenAWeek(ts int64) bool {
	checkTime := time.Unix(ts, 0)
	timeNow := time.Now()
	oneWeekAgo := timeNow.AddDate(0, 0, -7)

	if checkTime.Before(oneWeekAgo) {
		return true
	}

	return false

}

// Function to see if string within string
func Contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

// Function to see if string within string
func ContainsIP(cidrstring string, ip string) bool {
	_, netw, err := net.ParseCIDR(cidrstring)
	if err != nil {
		return false
	}

	ipaddress := net.ParseIP(ip)
	if ipaddress == nil {
		return false
	}

	if netw.Contains(ipaddress) {
		return true
	}

	return false
}

func GetIPaddressesFromChainIPv4(chainName string) ([]string, error) {
	var ips []string
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Println("GetIPaddressesFromChainIPv4:", err)
		return ips, err
	}

	rules, err := ipt.Stats("filter", chainName)
	if err != nil {
		log.Println("GetIPaddressesFromChainIPv4:", err)
		return ips, err
	}

	for _, line := range rules {
		for count, val := range line {
			if count == 7 {
				if net.ParseIP(val) == nil {
					ip, _, err := net.ParseCIDR(val)
					if err == nil {
						ips = AddIP(ips, ip.String())
					}
				} else {
					ips = AddIP(ips, val)
				}
			}
		}
	}

	return ips, nil
}

func GetTime() int64 {
	now := time.Now()
	sec := now.Unix()
	return sec
}

func InitializeIPTables(ipt *iptables.IPTables, chainName string) (string, error) {
	// Get existing chains from IPTABLES
	originaListChain, err := ipt.ListChains("filter")
	if err != nil {
		return "error", fmt.Errorf("failed to read iptables: %w", err)
	}

	// Search for INPUT in IPTABLES
	chain := "INPUT"
	if !Contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected INPUT chain")
	}

	// Search for FORWARD in IPTABLES
	chain = "FORWARD"
	if !Contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected FORWARD chain")
	}

	// Search for chainName in IPTABLES
	if Contains(originaListChain, chainName) {
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

func IptableHandle(proto string, task string, ipvar string, extraLog bool, chainName string, targetChain string) (string, error) {
	if extraLog {
		log.Println("iptableHandle:", proto, task, ipvar)
	}

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

	_, err = InitializeIPTables(ipt, chainName)
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
			log.Println("iptableHandler:", ipvar, "blocked.")
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
			if extraLog {
				log.Println("iptableHandler:", proto, err)
			}
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
