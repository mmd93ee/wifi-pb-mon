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

// Test to see if this is a Beacon frame then return the InformationElement
func Dot11BeaconInfoElement(p *gopacket.Packet, c chan *BeaconNode, filt string, debugOn bool) {

	source := *p
	beaconNode := BeaconNode{source.Metadata().Timestamp.String(), "", "", "", "", "", 0000, ""}

	dot11 := source.Layer(layers.LayerTypeDot11)
	dot11Info := source.Layer(layers.LayerTypeDot11InformationElement)

	if dot11 != nil {

		// Address1: Reciever address.  Address2: Transmitter/Source address.  Address3: BSSID/Destination
		dot11, _ := dot11.(*layers.Dot11)
		beaconNode.bssid = dot11.Address3.String()
		beaconNode.transmitter = dot11.Address2.String()
		beaconNode.receiver = dot11.Address1.String()
		beaconNode.pflag = dot11.Flags.String()
		beaconNode.ptype = dot11.Type.String()
		beaconNode.proto = dot11.Proto

		if debugOn {
			fmt.Printf("DEBUG: Found LayerTypeDot11 from %v", dot11.Address3.String())
		}
	}

	if dot11Info != nil {
		dot11InfoEl, _ := dot11Info.(*layers.Dot11InformationElement)
		if dot11InfoEl.ID.String() == layers.Dot11InformationElementIDSSID.String() {
			beaconNode.ssid = string(dot11InfoEl.Info)

			if debugOn {
				fmt.Printf("DEBUG: Found Dot11InformationElement with SSID %v", string(dot11InfoEl.Info))
			}
		}
	}

	// If we have set the filter to only focus on one BSSID then reset all others to blank
	if filt == "all" {

		if debugOn {
			fmt.Printf("Found packet and no filter applied to capture, putting to channel")
		}

		c <- &beaconNode
	} else if filt != beaconNode.bssid {

		if debugOn {
			fmt.Printf("Found packet not matching filter: %v, putting to channel", filterBSSID)
		}

		beaconNode.bssid = ""
		c <- &beaconNode
	} else {

		if debugOn {
			fmt.Printf("Found packet matching filter %v, putting to channel", filterBSSID)
		}

		c <- &beaconNode
	}
}

// Test to see if this is a Probe frame then return the InformationElement
func Dot11ProbeInfoElement(p *gopacket.Packet) {

}
