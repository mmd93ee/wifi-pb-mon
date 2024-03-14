package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

type beaconNode struct {
	timestamp string
	BSSID     string
	SSID      string
}

var (

	// Global variables
	// usage string = "USAGE: pb-monitor.go -i <interface name> -b <buffer entries> -r <Counter MAC Randomisation> -s <SSID filter value>"
	timeout time.Duration = 30 * time.Second

	// Command line variables
	iface      string
	pBuffer    int
	rDetect    bool
	filterSSID string
	debugOn    bool
)

func main() {

	// Set flags
	flag.StringVar(&iface, "i", "lo1", "Interface name to use")
	flag.IntVar(&pBuffer, "b", 1000, "Maximum queue size for packet decode")
	flag.BoolVar(&rDetect, "r", false, "Counter MAC Randomisation On")
	flag.StringVar(&filterSSID, "s", "all", "SSID Filter")
	flag.BoolVar(&debugOn, "d", false, "Debug On")
	flag.Parse()

	if debugOn {
		displayDevices()
	}

	// Print out command line arguments
	fmt.Println("Command Line Arguments:")
	fmt.Println("  Interface: (-i): ", iface)
	fmt.Println("  Packet Buffer Size (-b): ", pBuffer)
	fmt.Println("  Detect and Counter Random MAC (-r): ", rDetect)
	fmt.Println("  SSID Filter (-s): ", filterSSID)
	fmt.Println("  Debug (-d): ", debugOn)

	// Create a PacketSource and Channels for each analysis type
	packetSource := createPacketSource(iface)

	// Capture packets in the packetsource and then
	for packet := range packetSource.Packets() {
		isDot11Beacon(packet)
	}
}

func displayDevices() {

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	log.Print("Devices found:")
	for _, device := range devices {
		fmt.Println(" Name: ", device.Name)
		fmt.Println(" Description: ", device.Description)
		fmt.Println(" Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("  IP address: ", address.IP)
			fmt.Println("  Subnet mask: ", address.Netmask)
		}
	}
}
