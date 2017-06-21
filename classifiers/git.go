package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
	"strconv"
	"strings"
)

type GitClassifier struct{}

func (_ GitClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) < 4 {
		return false
	}

	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 9418 && dstPort != 9418 {
				return false
			}

			if applicationLayer := (*packet).ApplicationLayer(); applicationLayer != nil {
				payload := string(applicationLayer.Payload())
				payloadSlice := strings.Split(payload, "")
				payloadLength := len(payload)
				offset := 0
				for (offset + 4) < payloadLength {
					length := make([]string, 5)
					var git_pkt_len uint16
					copy(length, payloadSlice)
					length[4] = string(0)

					git_pkt_len, _ = strconv.Atoi(strings.Join(length, ""))
					if payloadLength < git_pkt_len || git_pkt_len == 0 {
						return false
					} else {
						offset += git_pkt_len
						payloadLength -= git_pkt_len
					}

				}

			} else {
				return false
			}

		} else {
			return false
		}
	}

	return true
}

func (_ GitClassifier) GetProtocol() godpi.Protocol {
	return godpi.Git
}
