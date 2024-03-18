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

// Test to see if this is a Beacon frame then return the InformationElement
func Dot11BeaconInfoElement(p *gopacket.Packet, c chan *BeaconNode) {

	source := *p
	beaconNode := BeaconNode{source.Metadata().Timestamp.String(), "", "", "", 0000, ""}

	dot11 := source.Layer(layers.LayerTypeDot11)
	dot11Info := source.Layer(layers.LayerTypeDot11InformationElement)

	if dot11 != nil {
		dot11, _ := dot11.(*layers.Dot11)
		beaconNode.BSSID = dot11.Address3.String()
		beaconNode.PFLAG = dot11.Flags.String()
		beaconNode.TYPE = dot11.Type.String()
		beaconNode.PROTO = dot11.Proto
	}

	if dot11Info != nil {
		dot11InfoEl, _ := dot11Info.(*layers.Dot11InformationElement)
		if dot11InfoEl.ID.String() == layers.Dot11InformationElementIDSSID.String() {
			beaconNode.SSID = string(dot11InfoEl.Info)
		}
	}

	c <- &beaconNode

}

// Test to see if this is a Probe frame then return the InformationElement
func Dot11ProbeInfoElement(p *gopacket.Packet) {

}
