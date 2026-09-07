package cmd

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/j0yb0y-m/deeznetz/scanner"
)

func RunPortscan(args []string) {
	fs := flag.NewFlagSet("portscan", flag.ExitOnError)
	ports := fs.String("p", "", "Ports to scan: single, list (80,443), or range (1-1000). Default: common ports")
	timeout := fs.Duration("t", 2*time.Second, "Connection timeout per port")
	workers := fs.Int("w", 100, "Number of concurrent connections")

	target := reorderArgs(fs, args)

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: missing target (IP address or CIDR).")
		fs.Usage()
		os.Exit(1)
	}

	portList, err := scanner.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	hosts, err := resolveTargets(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning target(s) %s (%d host(s)) on %d port(s)...\n",
		target, len(hosts), len(portList))
	fmt.Println("======================================")
	fmt.Println()

	totalOpen := 0
	totalHosts := 0
	for _, host := range hosts {
		openPorts := scanner.ScanHost(host, portList, *timeout, *workers)
		if len(openPorts) == 0 {
			continue
		}
		totalHosts++
		totalOpen += printPortResults(host, openPorts)
	}

	fmt.Printf("Found %d open port(s) on %d host(s).\n", totalOpen, totalHosts)
}

func printPortResults(ip net.IP, openPorts []int) int {
	fmt.Printf("%s:\n", ip)
	for _, port := range openPorts {
		svc := scanner.KnownService(port)
		if svc == "" {
			svc = "open"
		}
		label := fmt.Sprintf("%d/tcp", port)
		fmt.Printf("  %-10s%s\n", label, svc)
	}
	fmt.Println()
	return len(openPorts)
}

func resolveTargets(target string) ([]net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		return []net.IP{ip}, nil
	}

	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("target must be an IP address or CIDR: %v", err)
	}
	return scanner.CIDRHosts(ipnet.String())
}

func reorderArgs(fs *flag.FlagSet, args []string) string {
	valueFlags := map[string]bool{"-p": true, "-t": true, "-w": true,
		"--ports": true, "--timeout": true, "--workers": true}

	var flagArgs []string
	var target string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			name := a
			if idx := strings.IndexByte(a, '='); idx >= 0 {
				name = a[:idx]
			}
			if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		if target == "" {
			target = a
		}
	}

	if target != "" {
		flagArgs = append(flagArgs, target)
	}
	fs.Parse(flagArgs)
	return target
}
