package classifiers

import (
    "github.com/google/gopacket/layers"
    "github.com/mushorg/go-dpi"
)

type TelegramClassifier struct{}

func (_ TelegramClassifier) HeuristicClassify(flow *godpi.Flow) bool {

    if len(flow.Packets) == 0 {
        return false
    }

    for _, packet := range flow.Packets {
        if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
            dstPort := layer.(*layers.TCP).DstPort

            if len(flow.Packets) > 56 {
                applicationLayer := (*packet).ApplicationLayer()
                if applicationLayer != nil {
                    payload := applicationLayer.Payload()
                    if (payload[0] == 0xef) && (dstPort == 443 || dstPort == 80 || dstPort == 25) {

                        if (payload[1] != 0x7f) && (int(payload[1]*4) > len(flow.Packets)-1) {
                            return false
                        }

                    }
                } else {
                    return false
                }
            }
        }
    }

    return true

}

func (_ TelegramClassifier) GetProtocol() godpi.Protocol {
    return godpi.Telegram
}
