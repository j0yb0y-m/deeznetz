package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func inspectPacketPayload(packet gopacket.Packet) {
	// 1. Decode DNS Protocol Layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, ok := dnsLayer.(*layers.DNS)
		if ok {
			printDNSDetails(dns)
			printHexASCIIPayload("DNS Payload", dnsLayer.LayerContents())
		}
	}

	// 2. Decode Application Layer (HTTP / Raw Data)
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) == 0 {
			return
		}

		// Check if payload looks like plain-text HTTP
		payloadStr := string(payload)
		if isHTTP(payloadStr) {
			fmt.Println("--- [ HTTP Payload ] ---")
			fmt.Println(strings.TrimSpace(payloadStr))
			fmt.Println("------------------------")
			printHexASCIIPayload("HTTP Payload Hex/ASCII", payload)
		} else {
			printHexASCIIPayload("Raw Hex/ASCII Dump", payload)
		}
	}
}

func printHexASCIIPayload(label string, payload []byte) {
	if len(payload) == 0 {
		return
	}

	fmt.Printf("--- [ %s ] ---\n", label)
	fmt.Print(hex.Dump(payload))
	fmt.Println("------------------------------")
}

func printDNSDetails(dns *layers.DNS) {
	fmt.Printf("--- [ DNS Query/Response (ID: 0x%x) ] ---\n", dns.ID)
	fmt.Printf("  QR: %v (IsResponse: %v) | OpCode: %v | RCode: %v\n",
		dns.QR, dns.QR, dns.OpCode, dns.ResponseCode)

	// Print DNS Questions
	for _, q := range dns.Questions {
		fmt.Printf("  [Question] Domain: %s | Type: %s | Class: %s\n",
			string(q.Name), q.Type, q.Class)
	}

	// Print DNS Answers
	for _, a := range dns.Answers {
		fmt.Printf("  [Answer]   Domain: %s | Type: %s | TTL: %d",
			string(a.Name), a.Type, a.TTL)

		if a.IP != nil {
			fmt.Printf(" | IP: %s", a.IP.String())
		} else if len(a.CNAME) > 0 {
			fmt.Printf(" | CNAME: %s", string(a.CNAME))
		}
		fmt.Println()
	}
	fmt.Println("---------------------------------------")
}

// Helper to check for basic HTTP request/response signatures
func isHTTP(payload string) bool {
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1.", "HTTP/2."}
	for _, method := range httpMethods {
		if strings.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}

func defaultInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	for _, device := range devices {
		if device.Name != "lo" {
			return device.Name, nil
		}
	}
	if len(devices) > 0 {
		return devices[0].Name, nil
	}

	return "", fmt.Errorf("no capture interfaces found")
}

func main() {
	// 1. Define command-line flags
	iface := flag.String("i", "", "Network interface to capture on (default: first non-loopback interface)")
	filter := flag.String("f", "", "BPF filter expression (e.g., 'tcp port 80')")
	output := flag.String("o", "", "Output .pcap file path")
	snapLen := flag.Int("s", 1600, "Snapshot length in bytes")
	flag.Parse()

	if *iface == "" {
		var err error
		*iface, err = defaultInterface()
		if err != nil {
			log.Fatalf("Error finding a capture interface: %v", err)
		}
	}

	// 2. Open live capture handle
	handle, err := pcap.OpenLive(*iface, int32(*snapLen), true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", *iface, err)
	}
	defer handle.Close()

	// 3. Apply BPF filter if provided
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatalf("Invalid BPF filter: %v", err)
		}
		fmt.Printf("Filter applied: %q\n", *filter)
	}

	// 4. Setup PCAP Writer if output file flag is provided
	var pcapWriter *pcapgo.Writer
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer f.Close()

		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(uint32(*snapLen), handle.LinkType()); err != nil {
			log.Fatalf("Error writing pcap header: %v", err)
		}
		fmt.Printf("Saving output to: %s\n", *output)
	}

	// 5. Graceful shutdown on Ctrl+C to ensure files flush properly
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping capture...")
		handle.Close()
	}()

	// 6. Packet processing loop
	fmt.Printf("Sniffing on %s...\n", *iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet.String())
		inspectPacketPayload(packet)

		if pcapWriter != nil {
			err := pcapWriter.WritePacket(
				packet.Metadata().CaptureInfo,
				packet.Data(),
			)
			if err != nil {
				log.Printf("Failed to write packet to file: %v", err)
			}
		}
	}
}
