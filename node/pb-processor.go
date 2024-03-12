package main

import (
	"fmt"
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
func isDot11(packet gopacket.Packet) bool {

	dot11MgmtBeacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
	returnBool := false

	if dot11MgmtBeacon != nil {

		dot11Frame := packet.Layer(layers.LayerTypeDot11)
		p, _ := dot11Frame.(*layers.Dot11)

		fmt.Println("Beacon: ", p.Address1)
		fmt.Println()

		returnBool = true
	}

	return returnBool

}
