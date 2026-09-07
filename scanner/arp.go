package scanner

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

func GetInterfaceInfo(ifaceName string) (net.IP, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		return ip4, iface.HardwareAddr, nil
	}

	return nil, nil, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

func CIDRHosts(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %v", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	hosts := make([]net.IP, 0)

	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)

	for ipnet.Contains(ip) {
		hosts = append(hosts, append(net.IP(nil), ip...))
		inc(ip)
	}

	if ones < bits-1 {
		return hosts[1 : len(hosts)-1], nil
	}
	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func buildARPPacket(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(zeroMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func openARPHandle(iface string, readTimeout time.Duration) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", iface, err)
	}
	if err := handle.SetBPFFilter("arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}
	return handle, nil
}

func processPacket(packet gopacket.Packet, table *HostTable) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}

	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return
	}

	if arp.Operation != layers.ARPRequest && arp.Operation != layers.ARPReply {
		return
	}

	table.AddOrUpdate(
		net.IP(arp.SourceProtAddress),
		net.HardwareAddr(arp.SourceHwAddress),
	)
}

func RunActive(iface, cidr string, requestDelay, listenTimeout time.Duration, table *HostTable) error {
	srcIP, srcMAC, err := GetInterfaceInfo(iface)
	if err != nil {
		return err
	}

	hostIPs, err := CIDRHosts(cidr)
	if err != nil {
		return err
	}

	handle, err := openARPHandle(iface, 100*time.Millisecond)
	if err != nil {
		return err
	}
	defer handle.Close()

	table.AddOrUpdate(srcIP, srcMAC)

	fmt.Printf("Sending ARP requests to %d host(s) in %s...\n", len(hostIPs), cidr)
	for _, ip := range hostIPs {
		pkt, err := buildARPPacket(srcMAC, srcIP, ip)
		if err != nil {
			return err
		}
		if err := handle.WritePacketData(pkt); err != nil {
			return fmt.Errorf("error sending ARP request: %v", err)
		}
		time.Sleep(requestDelay)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	deadline := time.Now().Add(listenTimeout)

	fmt.Printf("Listening for ARP replies (timeout %s)...\n", listenTimeout)
	for time.Now().Before(deadline) {
		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}
		processPacket(packet, table)
	}

	return nil
}

func RunPassive(iface string, table *HostTable, stop <-chan struct{}) error {
	if _, _, err := GetInterfaceInfo(iface); err != nil {
		return err
	}

	handle, err := openARPHandle(iface, 100*time.Millisecond)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-stop:
			return nil
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			return err
		}
		processPacket(packet, table)
	}
}
