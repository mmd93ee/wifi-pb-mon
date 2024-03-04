package main

import (
	"flag"
)

var (
	usage      string = "USAGE: pb-monitor.go <interface name> <buffer entries>"
	iface             = flag.String("i", "wlan1", "Interface name to use")
	pbuffer           = flag.Int("b", 1000, "Maximum queue size for packet decode")
	rDetect           = flag.Bool("r", false, "Counter MAC Randomisation")
	filterSSID        = flag.String("s", "all", "Restrict to a single SSID (network or node)")
)

func main() {

}

// Set up connection to local interface
func createPacketSource PacketSource {}


// Capture packets

// Filter out non-beacon or non-broadcast or SSID matches

// Parse frame

// Store up to buffer size?
