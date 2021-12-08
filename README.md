![test](https://github.com/mushorg/go-dpi/actions/workflows/test.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/go-dpi/badge.svg?branch=master)](https://coveralls.io/github/mushorg/go-dpi?branch=master)
[![](https://godoc.org/github.com/mushorg/go-dpi?status.svg)](https://godoc.org/github.com/mushorg/go-dpi)
[![Go Report Card](https://goreportcard.com/badge/github.com/mushorg/go-dpi)](https://goreportcard.com/report/github.com/mushorg/go-dpi)

# go-dpi

go-dpi is an open source Go library for application layer protocol identification of traffic flows. In addition to its own heuristic methods, it contains wrappers for other popular and well-established libraries that also perform protocol identification, such as nDPI and libprotoident. It aims to provide a simple, easy-to-use interface and the capability to be extended by a developer with new detection methods and protocols.

It attempts to classify flows to different protocols regardless of the ports used. This makes it possible to detect protocols on non-standard ports, which is ideal for honeypots, as malware might often try and throw off detection methods by using non-standard and unregistered ports. Also, with its layered architecture, it aims to be fast in its detection, only using heavier classification methods when the faster ones fail.

It is being developed in the context of the Google Summer of Code 2017 program, under the mentorship of The Honeynet Project.

Please read the project's [Wiki page](https://github.com/mushorg/go-dpi/wiki) for more information.

For documentation, please check out the [godoc reference](https://godoc.org/github.com/mushorg/go-dpi).

## Example usage

The library and the modules APIs aim to be very simple and straightforward to use. The library relies on the [gopacket](https://godoc.org/github.com/google/gopacket) library and its Packet structure. Once you have a Packet in your hands, it's very easy to classify it with the library.
First of all you need to initialize the library. You can do that by calling:
```go
godpi.Initialize()
```

The `Initialize` method initializes all the selected modules in the library, by calling the `Initialize` method that they provide. It also creates the cache that is used to track the flows, which outdates unused flows after some minutes.

Then, you need a flow that contains the packet. You can get the flow a packet belongs to with the following call:

```go
flow, isNew := godpi.GetPacketFlow(packet)
```

That call returns the flow, as well as whether that flow is a new one (this packet is the first in the flow) or an existing one.

Afterwards, classifying the flow can be done by calling:

```go
result := godpi.ClassifyFlow(flow)
```

This returns the protocol guessed by the classifiers as well as the source, e.g. go-dpi or one of the wrappers.

Finally, once you are done with the library, you should free the used resources by calling:

```go
godpi.Destroy()
```

`Destroy` frees all the resources that the library is using, and calls the `Destroy` method of all the activated modules. It is essentially the opposite of the `Initialize` method.

A minimal example application is included below. It uses the library to classify a packet capture file, located at `/tmp/http.cap`. Note the helpful `godpi.ReadDumpFile` function that returns a channel with all the packets in the file.

```go
package main

import (
	"fmt"
	"github.com/mushorg/go-dpi"
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
)

func main() {
	godpi.Initialize()
	defer godpi.Destroy()
	packets, err := utils.ReadDumpFile("/tmp/http.cap")
	if err != nil {
		fmt.Println(err)
	} else {
		for packet := range packets {
			flow, _ := godpi.GetPacketFlow(packet)
			result := godpi.ClassifyFlow(flow)
			if result.Protocol != types.Unknown {
				fmt.Println(result.Source, "detected protocol", result.Protocol)
			} else {
				fmt.Println("No detection was made")
			}
		}
	}
}
```

## License

go-dpi is available under the MIT license and distributed in source code format.
