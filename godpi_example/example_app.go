package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mushorg/go-dpi"
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
)

func main() {
	var (
		count, idCount int
		protoCounts    map[types.Protocol]int
		packetChannel  <-chan gopacket.Packet
		err            error
	)

	protoCounts = make(map[types.Protocol]int)
	filename := flag.String("filename", "godpi_example/dumps/http.cap", "File to read packets from")
	device := flag.String("device", "", "Device to watch for packets")

	flag.Parse()

	if *device != "" {
		// check if interface was given
		fmt.Println("open live")
		handle, deverr := pcap.OpenLive(*device, 1024, false, time.Duration(-1))
		if deverr != nil {
			fmt.Println("Error opening device:", deverr)
			return
		}
		packetChannel = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	} else if _, ferr := os.Stat(*filename); !os.IsNotExist(ferr) {
		// check if file exists
		packetChannel, err = utils.ReadDumpFile(*filename)
	} else {
		fmt.Println("File does not exist:", *filename)
		return
	}
	fmt.Println("init")

	initErrs := godpi.Initialize()
	if len(initErrs) != 0 {
		for _, err := range initErrs {
			fmt.Println(err)
		}
		return
	}
	fmt.Println("init done")

	defer func() {
		godpi.Destroy()
		fmt.Println()
		fmt.Println("Number of packets:", count)
		fmt.Println("Number of packets identified:", idCount)
		fmt.Println("Protocols identified:\n", protoCounts)
	}()

	signalChannel := make(chan os.Signal, 1)
	fmt.Println("notify")
	signal.Notify(signalChannel, os.Interrupt)
	intSignal := false

	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	count = 0
	fmt.Println("waiting data")
	for packet := range packetChannel {
		flow, isNew := godpi.GetPacketFlow(packet)
		result := godpi.ClassifyFlow(flow)
		if result.Protocol != types.Unknown {
			fmt.Printf("Packet #%d: ", count+1)
			fmt.Println(result)
			idCount++
			protoCounts[result.Protocol]++
		} //else {
		//	fmt.Print("Could not identify")
		//}
		if isNew {
			fmt.Println(" (new flow)")
		} //else {
		//	fmt.Println()
		//}

		select {
		case <-signalChannel:
			fmt.Println("Received interrupt signal")
			fmt.Println(protoCounts)
			intSignal = true
		default:
		}
		if intSignal {
			break
		}
		count++
	}
}
