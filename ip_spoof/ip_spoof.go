package ip_spoof

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	interfaceName string
	intervalCount int
	spoofedIP     string
	packetCount   int
)

// Generate a random IP address
func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

// Start initiates the IP spoofing process
func Start() {
	// Prompt user for valid network interface
	for {
		fmt.Println("[+] Available network interfaces:")
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("[!] Error fetching network interfaces: %v", err)
		}

		for _, iface := range interfaces {
			fmt.Printf("- %s\n", iface.Name)
		}

		fmt.Print("[?] Enter network interface: ")
		fmt.Scanln(&interfaceName)
		if interfaceName == "h" || interfaceName == "home" {
			fmt.Printf("\n[$] Exiting IP Spoofing...")
			return
		}
		if handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever); err == nil {
			handle.Close()
			break
		} else {
			fmt.Printf("[!] Error: %v. Please enter a valid network interface.\n", err)
		}
	}

	// Prompt user for interval count
	for {
		fmt.Print("[?] Enter interval count (must be greater than 0): ")
		fmt.Scanln(&intervalCount)
		if intervalCount > 0 {
			break
		} else {
			fmt.Println("[!] Error: Interval count must be greater than 0.")
		}
	}

	// Open live packet capture on the specified interface
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[!] Error opening interface: %v", err)
	}
	defer handle.Close()

	// Set up signal handling to stop gracefully
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("[$] Starting IP spoofing on interface %s with interval %d...\n", interfaceName, intervalCount)
	fmt.Println("[!] Press Ctrl+C to stop.")

	// Initialize first spoofed IP
	spoofedIP = generateRandomIP()
	fmt.Printf("Initial spoofed IP: %s\n", spoofedIP)

	// Packet source for capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			go spoofPacket(packet, handle)
		case <-stop:
			fmt.Println("\n[$] Exiting IP spoofing...")
			return
		}
	}
}

func spoofPacket(packet gopacket.Packet, handle *pcap.Handle) {
	// Parse the original packet's layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ethLayer == nil || ipLayer == nil {
		return
	}

	// Extract Ethernet and IPv4 layer data
	eth, _ := ethLayer.(*layers.Ethernet)
	ip, _ := ipLayer.(*layers.IPv4)

	// Update packet count and rotate spoofed IP if needed
	packetCount++
	if packetCount > intervalCount {
		spoofedIP = generateRandomIP()
		packetCount = 1
		fmt.Printf("[+] New spoofed IP: %s\n", spoofedIP)
	}

	// Modify source IP to the current spoofed IP
	ip.SrcIP = net.ParseIP(spoofedIP)
	ip.Checksum = 0 // Let gopacket calculate the checksum

	// Recreate the packet
	newPacket := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	err := gopacket.SerializeLayers(newPacket, options, eth, ip)
	if err != nil {
		log.Printf("[!] Error serializing packet: %v", err)
		return
	}

	// Send the spoofed packet
	err = handle.WritePacketData(newPacket.Bytes())
	if err != nil {
		log.Printf("[!] Error sending spoofed packet: %v", err)
	} else {
		log.Printf("Spoofed packet sent: %s -> %s", spoofedIP, ip.DstIP)
	}
}
