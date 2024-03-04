package main

import (
	"flag"
	"fmt"
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

	// Print out command line arguments
	fmt.Printf(" Interface: %v\n Packet Buffer Size (packets): %v\n Detect and Counter Random MAC: %v\n SSID Filter: %v\n\n", iface, pBuffer, rDetect, filterSSID)

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
		mgmtBeacon, _ := dot11MgmtBeacon.(*layers.Dot11MgmtBeacon)
		fmt.Println("Beacon: ", mgmtBeacon.LayerContents())
		fmt.Println()
	}

	return packet
}
