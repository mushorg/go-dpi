package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi"
	"github.com/mushorg/go-dpi/classifiers"
	"github.com/mushorg/go-dpi/wrappers"
	"os"
	"os/signal"
)

func main() {
	var (
		count, idCount int
		protoCounts    map[godpi.Protocol]int = make(map[godpi.Protocol]int)
		packetChannel  <-chan gopacket.Packet
		flow           *godpi.Flow
		protocol       godpi.Protocol
		err            error
	)

	filename := flag.String("filename", "dumps/http.cap", "File to read packets from")

	flag.Parse()

	// check if file exists
	if _, err := os.Stat(*filename); os.IsNotExist(err) {
		fmt.Println("File does not exist:", *filename)
		return
	}

	wrappers.InitializeWrappers()

	defer func() {
		wrappers.DestroyWrappers()
		fmt.Println()
		fmt.Println("Number of packets:", count)
		fmt.Println("Number of packets identified:", idCount)
		fmt.Println("Protocols identified:\n", protoCounts)
	}()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	intSignal := false

	packetChannel, err = godpi.ReadDumpFile(*filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	count = 0
	for packet := range packetChannel {
		fmt.Printf("Packet %d: ", count+1)
		flow = godpi.CreateFlowFromPacket(&packet)
		protocol, _ = classifiers.ClassifyFlow(flow)
		if protocol != godpi.Unknown {
			fmt.Printf("Identified as %s\n", protocol)
			idCount++
			protoCounts[protocol]++
		} else {
			fmt.Println("Could not identify")
		}

		protocol, source := wrappers.ClassifyFlow(flow)
		if protocol != godpi.Unknown {
			fmt.Printf("%s says %s\n", source, protocol)
			idCount++
			protoCounts[protocol]++
		} else {
			fmt.Println("Wrappers could not identify")
		}

		select {
		case <-signalChannel:
			fmt.Println("Received interrupt signal")
			intSignal = true
		default:
		}
		if intSignal {
			break
		}
		count++
	}
	fmt.Println()
	fmt.Println("Number of packets:", count)
	fmt.Println("Number of packets identified:", idCount)
	fmt.Println("Protocols identified:\n", protoCounts)
}
