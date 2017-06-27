[![Build Status](https://travis-ci.org/mushorg/go-dpi.svg?branch=master)](https://travis-ci.org/mushorg/go-dpi)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/go-dpi/badge.svg?branch=master)](https://coveralls.io/github/mushorg/go-dpi?branch=master)
[![](https://godoc.org/github.com/mushorg/go-dpi?status.svg)](https://godoc.org/github.com/mushorg/go-dpi)

# go-dpi

go-dpi is an open source Go library for application layer protocol identification of traffic flows. In addition to its own heuristic methods, it contains wrappers for other popular and well-established libraries that also perform protocol identification, such as nDPI and libprotoident. It aims to provide a simple, easy-to-use interface and the capability to be easily extended by a developer with new detection methods and protocols.

It attempts to classify flows to different protocols regardless of the ports used. This makes it possible to detect protocols on non-standard ports, which is ideal for honeypots, as malware might often try and throw off detection methods by using non-standard and unregistered ports. Also, with its layered architecture, it aims to be fast in its detection, only using heavier classification methods when the simpler ones fail.

It is being developed in the context of the Google Summer of Code 2017 program, under the mentorship of The Honeynet Project.

Please read the project's [Wiki page](https://github.com/mushorg/go-dpi/wiki) for more information.

## Example usage

The library and the modules APIs aim to be very simple and straightforward to use. The library relies on the [gopacket](https://godoc.org/github.com/google/gopacket) library and its Packet structure. Once you have a Packet in your hands, it's very easy to classify it with the library.
First you need a flow that contains the packet. There is a helper function for constructing a flow from a single packet. Simply call:

```go
flow := godpi.CreateFlowFromPacket(&packet)
```

Afterwards, classifying the flow can be done by simply calling:

```go
proto, source := classifiers.ClassifyFlow(flow)
```

This returns the guess protocol by the classifiers as well as the source (which in this case will always be go-dpi).

The same thing applies for wrappers. However, for wrappers you also have to call the initialize function, and the destroy function before your program exits. All in all, the following is enough to run the wrappers:

```go
wrappers.InitializeWrappers()
defer wrappers.DestroyWrappers()
proto, source = wrappers.ClassifyFlow(flow)
```

A minimal example application is included below. It uses both the classifiers and wrappers to classify a simple packet capture file. Note the helpful `godpi.ReadDumpFile` function that simply returns a channel with all the packets in the file.

```go
package main

import "fmt"
import "github.com/mushorg/go-dpi"
import "github.com/mushorg/go-dpi/classifiers"
import "github.com/mushorg/go-dpi/wrappers"

func main() {
	packets, err := godpi.ReadDumpFile("/tmp/http.cap")
	wrappers.InitializeWrappers()
	defer wrappers.DestroyWrappers()
	if err != nil {
		fmt.Println(err)
	} else {
		for packet := range packets {
			flow := godpi.CreateFlowFromPacket(&packet)
			proto, source := classifiers.ClassifyFlow(flow)
			if proto != godpi.Unknown {
				fmt.Println(source, "detected protocol", proto)
			} else {
				fmt.Println("No detection made by classifiers")
			}
			proto, source = wrappers.ClassifyFlow(flow)
			if proto != godpi.Unknown {
				fmt.Println(source, "detected protocol", proto)
			} else {
				fmt.Println("No detection made by wrappers")
			}
		}
	}
}
```

## License

go-dpi is available under the MIT license and distributed in source code format.
