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
	dot11Probe := source.Layer(layers.LayerTypeDot11MgmtProbeReq)

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

	if nil != dot11Probe {
		dot11Pr, _ := dot11Probe.(*layers.Dot11MgmtProbeReq)
		beaconNode.ssid, _ = decodeProbeRequestLayer(dot11Pr)
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

func decodeProbeRequestLayer(probeLayer *layers.Dot11MgmtProbeReq) (ssid string, vendor []byte) {

	var body []byte
	body = probeLayer.LayerContents()
	ssid = "ssid to be determined"

	for i := uint64(0); i < uint64(len(body)); {
		id := layers.Dot11InformationElementID(body[i])
		i++
		switch id {
		case layers.Dot11InformationElementIDSSID:
			elemLen := uint64(body[i])
			i++
			if elemLen > 0 {
				ssid = string(body[i : i+elemLen])
				i += elemLen
			}
			break
		case layers.Dot11InformationElementIDVendor:
			vendor = body[i+1:]
			return
		default:
			elemLen := uint64(body[i])
			i += 1 + elemLen
			break
		}
	}

	return ssid, vendor
}
