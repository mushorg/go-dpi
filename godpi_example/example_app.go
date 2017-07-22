package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mushorg/go-dpi/classifiers"
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
	"github.com/mushorg/go-dpi/wrappers"
)

func main() {
	var (
		count, idCount int
		protoCounts    map[types.Protocol]int
		packetChannel  <-chan gopacket.Packet
		flow           *types.Flow
		protocol       types.Protocol
		err            error
	)

	protoCounts = make(map[types.Protocol]int)
	filename := flag.String("filename", "godpi_example/dumps/http.cap", "File to read packets from")
	device := flag.String("device", "", "Device to watch for packets")

	flag.Parse()

	if *device != "" {
		// check if interface was given
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

	for _, err := range wrappers.InitializeWrappers() {
		fmt.Printf("%s initialization error: %v\n", err.WrapperName, err)
		return
	}

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

	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	count = 0
	for packet := range packetChannel {
		fmt.Printf("Packet %d: ", count+1)
		flow = types.CreateFlowFromPacket(&packet)
		protocol, _ = classifiers.ClassifyFlow(flow)
		if protocol != types.Unknown {
			fmt.Printf("Identified as %s\n", protocol)
			idCount++
			protoCounts[protocol]++
		} else {
			fmt.Println("Could not identify")
		}

		wrapperProtocol, source := wrappers.ClassifyFlow(flow)
		if wrapperProtocol != types.Unknown {
			fmt.Printf("%s says %s\n", source, wrapperProtocol)
			if protocol == types.Unknown {
				idCount++
				protoCounts[wrapperProtocol]++
			} else if protocol != wrapperProtocol {
				// go-dpi and wrapper detected different protocols
				fmt.Printf("PROTOCOL MISMATCH! go-dpi identified flow "+
					"as %s, while %s detected it as %s\n", protocol, source, wrapperProtocol)
			}
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
}
