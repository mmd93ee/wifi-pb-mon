package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	BeaconString = "MgmtBeacon"
	ProbeString  = "MgmtProbeReq"
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
func Dot11GetElement(p *gopacket.Packet, cbeacon chan *BeaconNode, cprobe chan *BeaconNode, cnone chan *BeaconNode, debugOn bool) {

	source := *p
	beaconNode := BeaconNode{source.Metadata().Timestamp.String(), "", "", "", "", "", 0000, ""}
	dot11 := source.Layer(layers.LayerTypeDot11)
	dot11Info := source.Layer(layers.LayerTypeDot11InformationElement)

	if nil != dot11 {

		// Address1: Reciever address.  Address2: Transmitter/Source address.  Address3: BSSID/Destination
		dot11, _ := dot11.(*layers.Dot11)
		beaconNode.bssid = dot11.Address3.String()
		beaconNode.transmitter = dot11.Address2.String()
		beaconNode.receiver = dot11.Address1.String()
		beaconNode.pflag = dot11.Flags.String()
		beaconNode.ptype = dot11.Type.String()
		beaconNode.proto = dot11.Proto

	}

	if nil != dot11Info {
		dot11InfoEl, _ := dot11Info.(*layers.Dot11InformationElement)
		if dot11InfoEl.ID.String() == layers.Dot11InformationElementIDSSID.String() {
			beaconNode.ssid = string(dot11InfoEl.Info)

		}
	}

	// Work out which channel to return down
	if beaconNode.ptype == BeaconString {
		cbeacon <- &beaconNode
	} else if beaconNode.ptype == ProbeString {

		fmt.Printf("DEBUG: %v", source)
		cprobe <- &beaconNode
	} else {
		cnone <- &beaconNode
	}
}
