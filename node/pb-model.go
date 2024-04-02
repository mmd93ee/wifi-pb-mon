package main

import "log"

// A node represents an AP, device or other transmitting/recieving address including broadcast
type Node struct {
	// Adjacency information
	associations []*Node

	// Node data
	knownAs            string
	ssid               string
	bssid              string
	nodeType           string
	transmitterAddress string
	timesSeen          int
	strength           int
	lastSeen           string
	firstSeen          string
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

	if debugOn {
		log.Printf("Adding node %v to %v\n", inNode, graph)
	}

	return true
}
