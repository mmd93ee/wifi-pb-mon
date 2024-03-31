package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

type BeaconNode struct {
	timestamp   string
	bssid       string
	ssid        string
	pflag       string
	transmitter string
	receiver    string
	proto       uint8
	ptype       string
	sigStrength int8
}

var (

	// Global variables
	// usage string = "USAGE: pb-monitor.go -i <interface name> -b <buffer entries> -r <Counter MAC Randomisation> -s <SSID filter value>"
	timeout time.Duration = 30 * time.Second

	// Command line variables
	iface      string
	pBuffer    int
	rDetect    bool
	filterTran string
	debugOn    bool

	// Counters
	ProbeCount  int
	BeaconCount int
	NoneCount   int
)

func main() {

	// Set flags
	flag.StringVar(&iface, "i", "lo1", "Interface name to use")
	flag.IntVar(&pBuffer, "b", 1000, "Maximum queue size for packet decode")
	flag.BoolVar(&rDetect, "r", false, "Counter MAC Randomisation On")
	flag.StringVar(&filterTran, "f", "all", "Transmitter MAC Filter (not implemented yet)")
	flag.BoolVar(&debugOn, "d", false, "Debug On")
	flag.Parse()

	// Print out command line arguments
	fmt.Println("\n\nCommand Line Arguments:")
	fmt.Println("  Interface: (-i): ", iface)
	fmt.Println("  Packet Buffer Size (-b) : ", pBuffer)
	fmt.Println("  Detect and Counter Random MAC (-r): ", rDetect)
	fmt.Println("  Transmitter MAC Filter (not yet available) (-f): ", filterTran)
	fmt.Println("  Debug (-d): ", debugOn)

	// Initialiase Counters
	BeaconCount = 0
	ProbeCount = 0
	NoneCount = 0

	// Display the devices on the local machine
	if debugOn {
		displayDevices()
	}

	// Create a Graph model
	nodeGraph := newGraph(debugOn)

	fmt.Printf("Graph: %v\n", nodeGraph)

	// Create a PacketSource and Channels
	packetSource := createPacketSource(iface)

	chanBeacon := make(chan *BeaconNode)
	chanProbe := make(chan *BeaconNode)
	chanNone := make(chan *BeaconNode)

	// Capture packets in the packetsource
	for packet := range packetSource.Packets() {

		// Send for analysis against layer type.
		go Dot11GetElement(&packet, chanBeacon, chanProbe, chanNone, debugOn)

		select {

		case data := <-chanBeacon:

			BeaconCount++
			if debugOn && len(data.ssid) > 0 {
				PrintBeaconDetail("BEACON", data)
			}

		case data := <-chanProbe:

			ProbeCount++
			if debugOn {
				PrintBeaconDetail("PROBE", data)
			}

		// Do nothing channel - this is where anything that is not a Beacon or Probe ends up
		case <-chanNone:

			NoneCount++

		// Set a timeout on the channel to make sure we close the channel eventually if blocked.
		case <-time.After(timeout):
			err := "TIMEOUT ERROR ON CHANNEL: " + fmt.Sprint(timeout) + " Seconds with no data recieved"
			panic(err)

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
	fmt.Println("\n\nDevices found:")
	for _, device := range devices {
		fmt.Println("  Name: ", device.Name)
		fmt.Println("  Description: ", device.Description)
		fmt.Println("  Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("    IP address: ", address.IP)
			fmt.Println("    Subnet mask: ", address.Netmask)
		}
	}
}

func PrintBeaconDetail(t string, data *BeaconNode) {

	log.Printf("DEBUG: Probe Count: %s Beacon Count: %s Unmatched Count: %s\n\n %s PACKET: \n Time: %s\n BSSID: %s\n SSID: %s\n Transmitter: %v\n Receiver: %v\n Flags: %s\n Proto: %v\n Type: %s\n Signal Strength:%v\n\n",
		ProbeCount,
		BeaconCount,
		NoneCount,
		t,
		data.timestamp,
		data.bssid,
		data.ssid,
		data.transmitter,
		data.receiver,
		data.pflag,
		data.proto,
		data.ptype,
		data.sigStrength)
}
