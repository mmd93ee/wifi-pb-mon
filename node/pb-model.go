package main

import (
	"log"
)

// A node represents an AP, device or other transmitting/recieving address including broadcast
type Node struct {
	// Adjacency information
	associations []*Node

	// Node data
	knownAs              string
	ssid                 string
	bssid                []string
	nodeType             string
	transmitterAddresses []string
	timesSeen            int
	strength             []int8
	seen                 []string
}

type NodeList struct {
	nodes map[string]*Node
}

func newGraph(debugOn bool) NodeList {

	if debugOn {
		log.Printf("DEBUG: Creating Graph model\n")
	}

	return NodeList{
		nodes: make(map[string]*Node),
	}
}

// Beacon Packets all originate from a broadcasting access point.  Associations do not exist since they are advertising packets.
func addNodeFromBeacon(graph *NodeList, inNode *BeaconNode, debugOn bool) bool {

	newNode := createNodeFromBeacon(inNode)

	val, ok := graph.nodes[newNode.knownAs]
	if ok {
		// Found a matching knownAs in the Node List, update values
		val.timesSeen++
		val.strength = append(val.strength, newNode.strength[0])
		val.seen = append(val.seen, inNode.timestamp)

		if debugOn {
			log.Printf("DEBUG: Updating node %v, seen %v times on %v transmitting addresses with strength (last 5) %v\n",
				inNode.ssid,
				val.timesSeen,
				len(val.transmitterAddresses),
				val.strength[:5])
		}

	} else { // Not an existing SSID
		graph.nodes[newNode.knownAs] = &newNode
		val = graph.nodes[newNode.knownAs] // Set val to the newly created Node

		if debugOn {
			log.Printf("DEBUG: New node %v added to Graph List\n", val.knownAs)
		}
	}

	if val.nodeType == "MgmtProbeReq" { // Probe request, update the associations and make sure both ends of the probe exist

		if debugOn {
			log.Printf("DEBUG: Adding associations from probe request\n")
		}

		valAssoc, ok := graph.nodes[newNode.ssid] // Check if we have the node that is being probed

		if !ok { // Create a skeleton endpoint for the probe and add to the Graph List.

			if debugOn {
				log.Printf("DEBUG: Probe request to an undiscovered SSID: %v so adding as new node\n", val.ssid)
			}
			assocNode := Node{knownAs: val.ssid}
			graph.nodes[assocNode.knownAs] = &assocNode

			valAssoc = graph.nodes[newNode.knownAs]
		}

		// Add probe packet knownAs to the SSID knownAs and vice versa

		if debugOn {
			log.Printf("DEBUG: Adding %v to node %v and vice versa\n", valAssoc.knownAs, val.knownAs)
		}
		val.associations = append(val.associations, valAssoc)
		valAssoc.associations = append(valAssoc.associations, val)
	}

	return true
}

// Create a Node from a BeaconNode
func createNodeFromBeacon(beacon *BeaconNode) Node {

	n := Node{}

	// Data settings based on BeaconProbe type
	switch beacon.ptype {

	case "MgmtProbeReq":

		if debugOn {
			log.Printf("DEBUG: Probe request (%v), setting KnownAs to %v\n", beacon.ptype, beacon.transmitter)
		}

		n.knownAs = beacon.transmitter

	case "MgmtBeacon":

		if debugOn {
			log.Printf("DEBUG: Beacon request (%v), setting KnownAs to %v\n", beacon.ptype, beacon.ssid)
		}

		n.knownAs = beacon.ssid

	default:

		if debugOn {
			log.Printf("DEBUG: Default packet type applied to %v, setting KnownAs to %v\n", beacon.ptype, beacon.ssid)
		}

		n.knownAs = beacon.ssid
	}

	n.ssid = beacon.ssid
	n.bssid = append(n.bssid, beacon.bssid)
	n.nodeType = beacon.ptype
	n.transmitterAddresses = append(n.transmitterAddresses, beacon.transmitter)
	n.timesSeen = 1 // Default is 1, this may increase if it already exists in Node List
	n.strength = append(n.strength, beacon.sigStrength)
	n.seen = append(n.seen, beacon.timestamp) // This is now

	return n

}
