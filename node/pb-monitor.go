package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (

	// Global variables
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
	flag.PrintDefaults()

	createPacketSource()
}

// Set up connection to local interface
func createPacketSource() {

	handle, err := pcap.OpenLive(iface, 65536, true, time.Duration(timeout.Seconds()))
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("Packet: %v", packet) // Do something with a packet here.
	}
}

// Capture packets

// Filter out non-beacon or non-broadcast or SSID matches

// Parse frame

// Store up to buffer size?
