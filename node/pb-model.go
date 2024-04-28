package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// A node represents an AP, device or other transmitting/recieving address including broadcast
type Node struct {
	// Adjacency information
	Associations []string

	// Node data
	KnownAs              string
	SSID                 string
	BSSID                []string
	NodeType             string
	TransmitterAddresses []string
	TimesSeen            int
	Strength             []int8
	Seen                 []string
	FirstSeen            string
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
// Function takes a packet and then creates a new node.  The new node then either updates an existing or creates a new node.
func addNodeFromBeacon(graph *NodeList, inNode *BeaconNode, debugOn bool) bool {

	// In all cases create a new node as a base to work against
	newNode := createNodeFromBeacon(inNode)

	// See if the 'KnownAs' value exists in the list of all known nodes
	val, ok := graph.nodes[newNode.KnownAs]
	if ok {
		// Found a matching KnownAs in the Node List, update values.
		val.TimesSeen++
		val.Strength = updateBufferedStrength(val.Strength, inNode.sigStrength, debugOn)
		val.Seen = updateBufferedTimes(val.Seen, inNode.timestamp, debugOn)

		if debugOn {
			log.Printf("DEBUG: Updating node %v, seen %v times on %v transmitting addresses\n",
				inNode.ssid,
				val.TimesSeen,
				len(val.TransmitterAddresses))
		}

	} else { // Not an existing 'KnownAs' so we need a new node
		graph.nodes[newNode.KnownAs] = &newNode
		val = graph.nodes[newNode.KnownAs] // Set val to the newly created Node

		if debugOn {
			log.Printf("DEBUG: New node %v added to Graph List\n", val.KnownAs)
		}
	}

	if val.NodeType == "MgmtProbeReq" { // Probe request, update the associations and make sure both ends of the probe exist

		if debugOn {
			log.Printf("DEBUG: Adding associations from probe request\n")
		}

		valAssoc, ok := graph.nodes[newNode.SSID] // Check if we have the node that is being probed

		if !ok { // Create a skeleton endpoint for the probe and add to the Graph List.

			if debugOn {
				log.Printf("DEBUG: Probe request to an undiscovered SSID: %v so adding as new node\n", newNode.SSID)
			}
			assocNode := Node{KnownAs: newNode.SSID}
			graph.nodes[assocNode.KnownAs] = &assocNode

			valAssoc = graph.nodes[assocNode.KnownAs]
		}

		// Add unique probe packet KnownAs to the SSID KnownAs and vice versa

		// Check if valAssoc is in val.associations and if not then add it
		if !containsAssociation(val, valAssoc) {
			log.Println("*******************Matched Assoc 1")
			val.Associations = append(val.Associations, valAssoc.KnownAs)
		}

		// Check if val is in valAssoc.associations and if it is not then add it
		if !containsAssociation(valAssoc, val) {
			log.Println("*******************Matched Assoc 2")
			valAssoc.Associations = append(valAssoc.Associations, val.KnownAs)
		}

		// Remove SSID from the probe target - bit of a hack...
		val.SSID = ""

		if debugOn {
			log.Printf("DEBUG: Added %v to node %v and vice versa\n", valAssoc.KnownAs, val.KnownAs)
			log.Println("FROM NODE: ")
			PrintNodeDetail(val)
			log.Println("TO NODE: ")
			PrintNodeDetail(valAssoc)

		}
	}

	// Write out to the database folder
	writeToDatabase(val, dbName, debugOn)

	return true
}

// Create a Node from a BeaconNode to then be used to manipulate data into.
func createNodeFromBeacon(beacon *BeaconNode) Node {

	n := Node{}
	n.Strength = make([]int8, pBuffer)
	n.Seen = make([]string, pBuffer)

	// Data settings based on BeaconProbe type
	switch beacon.ptype {

	case "MgmtProbeReq":

		if debugOn {
			log.Printf("DEBUG: Probe request (%v), setting KnownAs to %v\n", beacon.ptype, beacon.transmitter)
		}

		n.KnownAs = beacon.transmitter

	case "MgmtBeacon":

		fmt.Println("DEBUG: ", len(strings.TrimLeft(beacon.ssid, " ")))

		for i := 0; i < len(beacon.ssid); i++ {
			fmt.Printf("********* Char: % +q **** ", beacon.ssid[i])
		}

		if debugOn {
			log.Printf("DEBUG: Beacon request (%v), setting KnownAs to ssid %v or transmitter %v (%T)\n", beacon.ptype, beacon.ssid, beacon.transmitter, beacon.ssid)
		}

		if len(strings.TrimLeft(beacon.ssid, " ")) > 0 {
			n.KnownAs = beacon.ssid

		} else {
			n.KnownAs = beacon.transmitter + "(GENERATED)"
		}

	default:

		if debugOn {
			log.Printf("DEBUG: Default packet type applied to %v, setting KnownAs to %v\n", beacon.ptype, beacon.ssid)
		}

		n.KnownAs = beacon.ssid
	}

	n.SSID = beacon.ssid
	n.BSSID = append(n.BSSID, beacon.bssid)
	n.NodeType = beacon.ptype
	n.TransmitterAddresses = append(n.TransmitterAddresses, beacon.transmitter)
	n.TimesSeen = 1                                                            // Default is 1, this may increase if it already exists in Node List
	n.Strength = updateBufferedStrength(n.Strength, beacon.sigStrength, false) // Turn off debug since overly noisy
	n.Seen = updateBufferedTimes(n.Seen, beacon.timestamp, false)              // Turn off debg since overly noisy
	n.FirstSeen = beacon.timestamp

	return n

}

// Stength and Seen need to be fixed length to avoid infinite growth
func updateBufferedStrength(strengths []int8, s int8, debugOn bool) []int8 {

	if debugOn {
		log.Printf("DEBUG: Updating Signal Strength buffer on node, value to add %v\n", s)
		log.Printf("DEBUG: Signal Strength buffer before change: %v\n", strengths)
	}

	// Pop and shift the slice - pop currently disappears - then add the new value to the end
	if len(strengths) > 0 {
		_, strengths = strengths[0], strengths[1:]
		strengths = append(strengths, s)
	} else {
		strengths = append(strengths, s)
	}

	if debugOn {
		log.Printf("DEBUG: Signal Strength buffer after change: %v\n", strengths)
	}

	return strengths

}

// Stength and Seen need to be fixed length to avoid infinite growth
func updateBufferedTimes(times []string, t string, debugOn bool) []string {

	if debugOn {
		log.Printf("DEBUG: Updating Times Seen buffer on node, value to add %v\n", t)
		//log.Printf("DEBUG: Times Seen buffer before change: %v\n", times)
	}

	// Pop and shift the slice - pop currently disappears - then add the new value to the end
	if len(times) > 0 {
		_, times = times[0], times[1:]
		times = append(times, t)
	} else {
		times = append(times, t)
	}

	return times

}

// Check if 'b' Node is in 'a' Node.associations.
func containsAssociation(a *Node, b *Node) bool {
	for _, v := range a.Associations {
		if v == b.KnownAs {
			return true
		}
	}
	return false
}

// Marshall out to json and write to the database folder
func writeToDatabase(node *Node, dbName string, debugOn bool) bool {

	if debugOn {
		log.Printf("DEBUG: Writing %v out to database folder %v", node.KnownAs, dbName)
	}

	// Create json string
	jsonOut, jsonErr := json.Marshal(*node)

	if jsonErr != nil {
		panic(jsonErr)
	}

	// Create database subfolder
	dirErr := os.MkdirAll(dbName, 0666)

	if dirErr != nil {
		panic(dirErr)
	}

	// Write string to the file at path 'dbName / KnownAs'
	fileOutPath := dbName + string(filepath.Separator) + node.KnownAs
	fileErr := os.WriteFile(fileOutPath, jsonOut, os.ModePerm)

	if fileErr != nil {
		panic(fileErr)
	}

	return true
}
