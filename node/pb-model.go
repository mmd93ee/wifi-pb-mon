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

func addNodeFromBeacon(graph *NodeList, inNode *BeaconNode, debugOn bool) bool {

	newNode := createNodeFromBeacon(inNode)

	val, ok := graph.nodes[newNode.knownAs]
	if ok {
		// Found a matching knownAs in the Node List, update values
		val.timesSeen++
		val.strength = append(val.strength, newNode.strength[0])
		val.seen = append(val.seen, inNode.timestamp)

		if debugOn {
			log.Printf("DEBUG: Updating node %v, seen %v times on %v transmitting addresses with strength (last 5) %v\n\n",
				inNode.ssid,
				val.timesSeen,
				len(val.transmitterAddresses),
				val.strength[:5])
		}

	} else { // Not an existing SSID
		graph.nodes[newNode.knownAs] = &newNode

		if debugOn {
			log.Printf("DEBUG: New node %v added to Graph List\n\n", inNode.ssid)
		}
	}

	return true
}

// Create a Node from a BeaconNode
func createNodeFromBeacon(beacon *BeaconNode) Node {

	n := Node{}

	n.knownAs = beacon.ssid // All Beaconing nodes are known by the SSID
	n.ssid = beacon.ssid
	n.bssid = append(n.bssid, beacon.bssid)
	n.nodeType = beacon.ptype
	n.transmitterAddresses = append(n.transmitterAddresses, beacon.transmitter)
	n.timesSeen = 1 // Default is 1, this may increase if it already exists in Node List
	n.strength = append(n.strength, beacon.sigStrength)
	n.seen = append(n.seen, beacon.timestamp) // This is now

	return n

}
