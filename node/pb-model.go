package main

import "log"

// A node represents an AP, device or other transmitting/recieving address including broadcast
type Node struct {
	// Adjacency information
	inNodes  []*Node
	outNodes []*Node

	// Node data
	knownAs            string
	SSID               string
	BSSID              string
	nodeType           string
	transmitterAddress string
	timesSeen          int
	strength           int
	lastSeen           string
	firstSeen          string
}

type Graph struct {
	nodes map[string]*Node
}

func newGraph(debug bool) *Graph {

	if debugOn {
		log.Printf("DEBUG: Creating Graph model\n")
	}
	return &Graph{
		nodes: make(map[string]*Node),
	}
}

func addNode(debug bool) {

}
