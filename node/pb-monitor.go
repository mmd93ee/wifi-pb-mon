package main

import (
	"fmt"
	"log"
	"os"
)

// Parse command line args for
//	interface to use
//	storage buffer size
//	try to detect MAC randomisation
//	specific SSID

func main() {

	var usage string = "USAGE: pb-monitor.go <interface name> <buffer entries>"

	var s, sep string
	for i := 1; i < len(os.Args); i++ {
		s += sep + os.Args[i]
		sep = " "
	}

	if len(os.Args) != 3 {
		fmt.Printf("%s \n", usage)
		log.Fatal("Incorrect number of command line arguments.")
	}

	fmt.Println(s)

}

// Set up connection to local interface

// Capture packets

// Filter out non-beacon or non-broadcast or SSID matches

// Parse frame

// Store up to buffer size?
