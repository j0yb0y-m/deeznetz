package main

import (
	"fmt"
	"os"

	"github.com/j0yb0y-m/deeznetz/cmd"
)

var version = "dev"

func printUsage() {
	fmt.Fprintf(os.Stderr, `deeznetz - Network packet sniffer & ARP scanner

Usage:
  deeznetz [subcommand] [flags]

Subcommands:
  arp         Active/passive ARP network scanner
  portscan    Lightweight TCP port scanner
  (none)      Packet capture mode (default)

Examples:
  deeznetz arp -r 192.168.1.0/24     Active scan a subnet
  deeznetz arp -p -i eth0            Passive ARP listening
  deeznetz arp -r 10.0.0.0/24 -i eth0 -timeout 5s
  deeznetz arp -r 192.168.1.0/24 -scan       ARP scan + port scan hosts
  deeznetz portscan 192.168.0.109            Port scan a host
  deeznetz portscan 192.168.0.0/24 -p 80,443,8000-9000
  deeznetz -i eth0 -f "tcp port 80"  Capture HTTP traffic
  deeznetz -o capture.pcap           Save capture to file
`)
}

func main() {
	if len(os.Args) < 2 {
		cmd.RunCapture(os.Args[1:])
		return
	}

	switch os.Args[1] {
	case "arp":
		cmd.RunARP(os.Args[2:])
	case "portscan":
		cmd.RunPortscan(os.Args[2:])
	case "--version", "-v", "version":
		fmt.Printf("deeznetz %s\n", version)
	case "--help", "-h", "help":
		printUsage()
	default:
		if os.Args[1][0] == '-' {
			cmd.RunCapture(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}
}
