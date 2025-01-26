package arp_poison

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Host struct {
	IPAddress   string
	MACAddress  string
	HostName    string
	IsReachable bool
}

// pingHost checks if the given IP is reachable using ICMP (ping)
func pingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-w", "1", ip) // Linux-specific; adjust for Windows
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return err == nil
}

// getMACAddress sends an ARP request to get the MAC address of a host
func getMACAddress(interfaceName string, ip string) string {
	handle, err := pcap.OpenLive(interfaceName, 1600, false, 1*time.Second)
	if err != nil {
		log.Printf("Error opening device %s: %v", interfaceName, err)
		return "Unknown"
	}
	defer handle.Close()

	// Construct ARP request
	srcMAC := getInterfaceMAC(interfaceName)
	srcIP := getInterfaceIP(interfaceName)

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(ip).To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, options, &eth, &arp)
	if err != nil {
		log.Printf("Error serializing ARP request: %v", err)
		return "Unknown"
	}

	// Send the ARP request
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Printf("Error sending ARP request to %v: %v", ip, err)
		return "Unknown"
	}

	// Listen for ARP replies
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(20 * time.Second) // Set timeout to 3 seconds

	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpPacket := arpLayer.(*layers.ARP)
				if net.IP(arpPacket.SourceProtAddress).Equal(net.ParseIP(ip)) {
					return net.HardwareAddr(arpPacket.SourceHwAddress).String()
				}
			}
		case <-timeout:
			return "Unknown"
		}
	}
}

// getHostName performs a reverse DNS lookup for the given IP
func getHostName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "Unknown"
	}
	return strings.TrimSuffix(names[0], ".")
}

// getInterfaceMAC retrieves the MAC address of the specified interface
func getInterfaceMAC(interfaceName string) net.HardwareAddr {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Printf("Error fetching interface %s: %v", interfaceName, err)
		return nil
	}
	return iface.HardwareAddr
}

// getInterfaceIP retrieves the IPv4 address of the specified interface
func getInterfaceIP(interfaceName string) net.IP {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Error fetching interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Error fetching addresses for interface %s: %v", interfaceName, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP
		}
	}
	log.Fatalf("No IPv4 address found for interface %s", interfaceName)
	return nil
}

// scanNetwork scans the entire subnet for active and inactive devices
func scanNetwork(interfaceName string, subnet string) {
	var wg sync.WaitGroup
	hosts := make(chan Host, 256)

	fmt.Printf("%-15s %-17s %-30s\n", "IP Address", "MAC Address", "Host Name")
	for i := 1; i < 255; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ip := fmt.Sprintf("%s.%d", subnet, i)
			if pingHost(ip) {
				mac := getMACAddress(interfaceName, ip)
				hostName := getHostName(ip)

				hosts <- Host{
					IPAddress:   ip,
					MACAddress:  mac,
					HostName:    hostName,
					IsReachable: true,
				}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(hosts)
	}()

	for host := range hosts {
		fmt.Printf("%-15s %-17s %-30s\n", host.IPAddress, host.MACAddress, host.HostName)
	}
	pStart(interfaceName) //Here we call the Poisoning code
}

func Start() {
	var interfaceName string

	fmt.Println("Available network interfaces:")
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Error fetching network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		fmt.Printf("- %s\n", iface.Name)
	}
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter the network interface name: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("\nError reading input:", err)
			continue
		}
		interfaceName = strings.TrimSpace(input)

		if interfaceName == "h" || interfaceName == "home" {
			fmt.Printf("\nExiting ARP Poisoning...")
			return
		}

		// Validate if the interface exists
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			fmt.Printf("Invalid interface name '%s': %v\n", interfaceName, err)
			continue
		}

		// Validate the interface has an IPv4 address
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			fmt.Printf("No IP address found for interface '%s'\n", interfaceName)
			continue
		}
		break
	}

	interfaceIP := getInterfaceIP(interfaceName)
	subnet := strings.Join(strings.Split(interfaceIP.String(), ".")[:3], ".")
	fmt.Printf("Scanning network: %s.0/24...\n", subnet)
	scanNetwork(interfaceName, subnet)
}
