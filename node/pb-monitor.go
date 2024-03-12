package main

import (
	"flag"
	"fmt"
	"log"
	"time"

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
	fmt.Println(" Interface: ", iface)
	fmt.Println(" Packet Buffer Size (packets): ", pBuffer)
	fmt.Println(" Detect and Counter Random MAC: ", rDetect)
	fmt.Println(" SSID Filter: ", filterSSID)
	fmt.Println(" Debug: ", debugOn)

	// Create a PacketSource
	packetSource := createPacketSource(iface)

	for packet := range packetSource.Packets() {

		if isDot11(packet) {
			if debugOn {
				log.Println("DEBUG: Found 802.11 Management Beacon Layer")
			}
		}
	}
}

func displayDevices() {

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

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
}
