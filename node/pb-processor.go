package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Set up connection to local interface
func createPacketSource(iface string) *gopacket.PacketSource {

	if debugOn {
		log.Print("DEBUG: Creating PacketSource against interface ", iface)
	}

	handle, err := pcap.OpenLive(iface, 65536, true, time.Duration(timeout.Seconds()))
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource
}

// Filter to just Ethernet Packets type 04x00 or 08x00
func Dot11Beacon(p gopacket.Packet) beaconNode {

	dot11MgmtBeacon := p.Layer(layers.LayerTypeDot11MgmtBeacon)
	metaData := p.Metadata()
	r := beaconNode{}

	if dot11MgmtBeacon != nil {

		if debugOn {
			log.Print("DEBUG: Found Dot11 Management Beacon.")
		}

		// Create the frame, metadata and mgmt node information
		dot11Frame := p.Layer(layers.LayerTypeDot11)
		node, _ := dot11Frame.(*layers.Dot11)

		r = beaconNode{timestamp: metaData.Timestamp.String(), BSSID: string(node.Address3), SSID: string(node.Address4)}
	}

	return r
}

func isDot11Beacon(p gopacket.Packet) bool {

	dot11MgmtBeacon := p.Layer(layers.LayerTypeDot11MgmtBeacon)
	isDot11 := false

	if dot11MgmtBeacon != nil {

		if debugOn {
			log.Print("DEBUG: Found Dot11 Management Beacon.")
		}

		isDot11 = true
	}
	return isDot11
}
