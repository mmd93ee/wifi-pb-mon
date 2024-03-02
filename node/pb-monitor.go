package main

import(
	"fmt"
	"os"
)

// Parse command line args for 
//	interface to use 
//	storage buffer size 
//	try to detect MAC randomisation 
//	specific SSID

func main()  {
	var s, sep string
	for i := 1; i < len(os.Args); i++ {
		s += s + os.Args[i]
		s = " "
	}
	fmt.Println(s)

}	


# Set up connection to local interface

# Capture packets

# Filter out non-beacon or non-broadcast or SSID matches

# Parse frame

# Store up to buffer size?