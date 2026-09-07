package cmd

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/j0yb0y-m/deeznetz/scanner"
)

func RunARP(args []string) {
	fs := flag.NewFlagSet("arp", flag.ExitOnError)
	rangeCIDR := fs.String("r", "", "CIDR range to scan in active mode (e.g., 192.168.1.0/24)")
	passive := fs.Bool("p", false, "Run in passive mode (listen for ARP traffic)")
	iface := fs.String("i", "", "Network interface (default: first non-loopback)")
	timeout := fs.Duration("timeout", 3*time.Second, "Response timeout for active scan")
	delay := fs.Duration("delay", 10*time.Millisecond, "Delay between ARP requests")
	doPortScan := fs.Bool("scan", false, "Port-scan discovered hosts after the scan")
	scanPorts := fs.String("scan-ports", "", "Ports to scan on discovered hosts (default: common ports)")
	scanTimeout := fs.Duration("scan-timeout", 2*time.Second, "Connection timeout per port")
	scanWorkers := fs.Int("scan-workers", 100, "Number of concurrent port connections")
	fs.Parse(args)

	if *rangeCIDR == "" && !*passive {
		*passive = true
	}

	if *rangeCIDR != "" && *passive {
		fmt.Fprintln(os.Stderr, "Error: -r (active) and -p (passive) are mutually exclusive.")
		fs.Usage()
		os.Exit(1)
	}

	if *iface == "" {
		var err error
		*iface, err = defaultInterface()
		if err != nil {
			log.Fatalf("Error finding interface: %v", err)
		}
	}

	srcIP, srcMAC, err := scanner.GetInterfaceInfo(*iface)
	if err != nil {
		log.Fatalf("Error getting interface info: %v", err)
	}

	fmt.Printf("Using interface: %s\n", *iface)
	fmt.Printf("Source IP: %s  MAC: %s\n", srcIP, srcMAC)

	manufPath, err := scanner.EnsureManuf()
	if err != nil {
		log.Printf("Warning: %v (vendor names will be 'Unknown')", err)
	} else {
		if _, err := scanner.LoadManuf(manufPath); err != nil {
			log.Printf("Warning: error loading OUI database %s: %v", manufPath, err)
		} else {
			fmt.Printf("OUI database: %s\n", manufPath)
		}
	}
	fmt.Println()

	table := scanner.NewHostTable()

	if *rangeCIDR != "" {
		runActiveScan(*iface, *rangeCIDR, *delay, *timeout, table)
	} else {
		runPassiveScan(*iface, table)
	}

	printResults(table)

	if *doPortScan {
		runDiscoveredPortScan(table, *scanPorts, *scanTimeout, *scanWorkers)
	}
}

func runDiscoveredPortScan(table *scanner.HostTable, ports string, timeout time.Duration, workers int) {
	hosts := table.GetAll()
	if len(hosts) == 0 {
		fmt.Println("\nNo hosts to port-scan.")
		return
	}

	portList, err := scanner.ParsePorts(ports)
	if err != nil {
		log.Fatalf("Invalid port specification %q: %v", ports, err)
	}

	fmt.Printf("\nPort-scanning %d discovered host(s) on %d port(s)...\n",
		len(hosts), len(portList))
	fmt.Println("======================================")
	fmt.Println()

	totalOpen := 0
	totalHosts := 0
	for _, h := range hosts {
		openPorts := scanner.ScanHost(h.IP, portList, timeout, workers)
		if len(openPorts) == 0 {
			continue
		}
		totalHosts++
		totalOpen += printPortResults(h.IP, openPorts)
	}

	fmt.Printf("Found %d open port(s) on %d host(s).\n", totalOpen, totalHosts)
}

func runActiveScan(iface, cidr string, delay, timeout time.Duration, table *scanner.HostTable) {
	fmt.Println("Mode: ACTIVE")
	fmt.Println("======================================")

	if err := scanner.RunActive(iface, cidr, delay, timeout, table); err != nil {
		log.Fatalf("Scan error: %v", err)
	}
}

func runPassiveScan(iface string, table *scanner.HostTable) {
	fmt.Println("Mode: PASSIVE")
	fmt.Println("======================================")
	fmt.Println("Listening for ARP traffic... Press Ctrl+C to stop.")
	fmt.Println()

	stop := make(chan struct{}, 1)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping passive scan...")
		stop <- struct{}{}
	}()

	if err := scanner.RunPassive(iface, table, stop); err != nil {
		log.Fatalf("Scan error: %v", err)
	}
}

func printResults(table *scanner.HostTable) {
	hosts := table.GetAll()
	if len(hosts) == 0 {
		fmt.Println("No hosts discovered.")
		return
	}

	fmt.Println()
	fmt.Printf("%-16s %-18s %-30s %s\n", "IP", "MAC", "VENDOR", "LAST SEEN")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, h := range hosts {
		fmt.Printf("%-16s %-18s %-30s %s\n",
			h.IP, h.MAC, h.Vendor, h.LastSeen.Format("15:04:05"))
	}

	fmt.Println()
	fmt.Printf("%d host(s) discovered.\n", len(hosts))
}
