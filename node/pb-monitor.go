package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type BeaconNode struct {
	timestamp string
	BSSID     string
	SSID      string
	PFLAG     string
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
	fmt.Println("  Packet Buffer Size (-b) : ", pBuffer)
	fmt.Println("  Detect and Counter Random MAC (-r): ", rDetect)
	fmt.Println("  SSID Filter (-s): ", filterSSID)
	fmt.Println("  Debug (-d): ", debugOn)

	// Create a PacketSource and Channels
	packetSource := createPacketSource(iface)
	chanBeacon := make(chan *BeaconNode)
	chanProbe := make(chan *layers.Dot11InformationElement)

	// Capture packets in the packetsource
	for packet := range packetSource.Packets() {

		// Send for analysis against layer type.
		go Dot11BeaconInfoElement(&packet, chanBeacon)
		go Dot11ProbeInfoElement(&packet)

		select {
		case data := <-chanBeacon:
			fmt.Printf("Time: %s\n BSSID: %s\n SSID: %s\n Flags: %s",
				data.timestamp,
				data.BSSID,
				data.SSID,
				data.PFLAG)
		case data := <-chanProbe:
			fmt.Printf("Fail: %T", data)
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
