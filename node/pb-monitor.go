package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
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
	timeout time.Duration = 30 * time.Second

	// Command line variables
	iface      string
	pBuffer    int
	rDetect    bool
	filterTran string
	debugOn    bool
	dbName     string

	// Counters
	ProbeCount  int
	BeaconCount int
	NoneCount   int

	// Data model
	NodeGraph NodeList
)

func main() {

	// Set flags
	flag.StringVar(&iface, "i", "lo1", "Interface name to use")
	flag.IntVar(&pBuffer, "b", 10, "Maximum queue size for packet decode")
	flag.BoolVar(&rDetect, "r", false, "Counter MAC Randomisation On")
	flag.StringVar(&filterTran, "f", "all", "Transmitter MAC Filter (not implemented yet)")
	flag.BoolVar(&debugOn, "d", false, "Debug On")
	flag.StringVar(&dbName, "db", strconv.FormatInt(time.Now().Unix(), 10), "Name of the folder in the database, default unixtime")
	flag.Parse()

	// Print out command line arguments
	fmt.Println("\n\nCommand Line Arguments:")
	fmt.Println("  Interface: (-i): ", iface)
	fmt.Println("  Packet Buffer Size (-b) : ", pBuffer)
	fmt.Println("  Detect and Counter Random MAC (-r): ", rDetect)
	fmt.Println("  Transmitter MAC Filter (not yet available) (-f): ", filterTran)
	fmt.Println("  Database Folder (-db): ", dbName)
	fmt.Println("  Debug (-d): ", debugOn)

	// Initialiase Counters
	BeaconCount = 0
	ProbeCount = 0
	NoneCount = 0

	// Set up the Graph data model

	// Display the devices on the local machine
	if debugOn {
		displayDevices()
	}

	// Create a Graph model
	NodeGraph = newGraph(debugOn)

	fmt.Printf("Graph: %v\n", NodeGraph)

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

			if addNodeFromBeacon(&NodeGraph, data, debugOn) {
				if debugOn {
					log.Printf("DEBUG: Successfully processed BeaconNode (Beacon) for %v\n\n", data.ssid)
				}
			}

		case data := <-chanProbe:

			ProbeCount++
			if debugOn {
				PrintBeaconDetail("PROBE", data)
			}

			if addNodeFromBeacon(&NodeGraph, data, debugOn) {
				if debugOn {
					log.Printf("DEBUG: Successfully processed BeaconNode (Probe) for %v\n\n", data.ssid)
				}
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

	log.Printf("DEBUG: ***** PACKET CAPTURED *****\n TOTALS:\n Probe Count: %v\n Beacon Count: %v (%v SSIDs)\n Unmatched Count: %v\n\n %s: \n Time: %s\n BSSID: %s\n SSID: %s\n Transmitter: %v\n Receiver: %v\n Flags: %s\n Proto: %v\n Type: %s\n Signal Strength:%v\n\n",
		ProbeCount,
		BeaconCount,
		len(NodeGraph.nodes),
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

func PrintNodeDetail(data *Node) {

	assocString := ""

	for _, a := range data.associations {

		addresses := "Node Addresses: "

		for _, b := range a.transmitterAddresses {
			addresses = addresses + b + " "
		}

		assocString = assocString + addresses + " (Known As: " + a.knownAs + ") "
	}

	log.Printf("DEBUG: NODE:\n Known As: %s\n First Seen: %s\n SSID: %s\n BSSID: %s\n Node Type: %v\n Transmitter Addresses: %v\n Times Seen: %v\n Strengths: %v\n Seen: %s\n Associations: %v\n\n",
		data.knownAs,
		data.firstSeen,
		data.ssid,
		data.bssid,
		data.nodeType,
		data.transmitterAddresses,
		data.timesSeen,
		data.strength,
		data.seen,
		assocString)
}
