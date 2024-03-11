package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (

	// Global variables
	// usage string = "USAGE: pb-monitor.go -i <interface name> -b <buffer entries> -r <Counter MAC Randomisation> -s <SSID filter value>"
	timeout time.Duration = 30 * time.Second

	// Command line variables
	iface      string
	pBuffer    int
	rDetect    bool
	filterSSID string
)

func main() {

	// Set flags
	flag.StringVar(&iface, "i", "lo1", "Interface name to use")
	flag.IntVar(&pBuffer, "b", 1000, "Maximum queue size for packet decode")
	flag.BoolVar(&rDetect, "r", false, "Counter MAC Randomisation")
	flag.StringVar(&filterSSID, "s", "all", "SSID Filter")
	flag.Parse()

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print out command line arguments
	fmt.Println("Command Line Arguments:")
	fmt.Println(" Interface: ", iface)
	fmt.Println(" Packet Buffer Size (packets): ", pBuffer)
	fmt.Println(" Detect and Counter Random MAC: ", rDetect)
	fmt.Println(" SSID Filter: ", filterSSID)

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println(" Name: ", device.Name)
		fmt.Println(" Description: ", device.Description)
		fmt.Println(" Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("  IP address: ", address.IP)
			fmt.Println("  Subnet mask: ", address.Netmask)
		}
	}

	// Create a PacketSource
	packetSource := createPacketSource()

	for packet := range packetSource.Packets() {
		isDot11(packet)
	}
}

// Set up connection to local interface
func createPacketSource() *gopacket.PacketSource {

	handle, err := pcap.OpenLive(iface, 65536, true, time.Duration(timeout.Seconds()))
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource
}

// Filter to just Ethernet Packets type 04x00 or 08x00
func isDot11(packet gopacket.Packet) gopacket.Packet {

	dot11MgmtBeacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon)

	if dot11MgmtBeacon != nil {
		dot11Frame := packet.Layer(layers.LayerTypeDot11)
		p, _ := dot11Frame.(*layers.Dot11)

		fmt.Println("Beacon: ", p.Address1)
		fmt.Println()
	}

	return packet
}
