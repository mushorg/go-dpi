package wrappers

// #include "wrappers_config.h"
// #cgo CFLAGS: -I/usr/local/include/
// #cgo LDFLAGS: -Wl,-Bstatic -lndpi -Wl,-Bdynamic -lpcap -lm -pthread
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"unsafe"

	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi/types"
	"github.com/pkg/errors"
)

// ndpiCodeToProtocol maps the nDPI protocol codes to go-dpi protocols.
var ndpiCodeToProtocol = map[uint32]types.Protocol{
	7:   types.HTTP,    // NDPI_PROTOCOL_HTTP
	5:   types.DNS,     // NDPI_PROTOCOL_DNS
	92:  types.SSH,     // NDPI_PROTOCOL_SSH
	127: types.RPC,     // NDPI_PROTOCOL_DCERPC
	3:   types.SMTP,    // NDPI_PROTOCOL_MAIL_SMTP
	88:  types.RDP,     // NDPI_PROTOCOL_RDP
	16:  types.SMB,     // NDPI_PROTOCOL_SMB
	81:  types.ICMP,    // NDPI_PROTOCOL_IP_ICMP
	1:   types.FTP,     // NDPI_PROTOCOL_FTP_CONTROL
	91:  types.SSL,     // NDPI_PROTOCOL_SSL
	64:  types.SSL,     // NDPI_PROTOCOL_SSL_NO_CERT
	10:  types.NetBIOS, // NDPI_PROTOCOL_NETBIOS
}

// NDPIWrapperName is the identification of the nDPI library.
const NDPIWrapperName = "nDPI"

// NDPIWrapperProvider provides NDPIWrapper with the implementations of the
// methods to use.
type NDPIWrapperProvider struct {
	ndpiInitialize    func() int32
	ndpiDestroy       func()
	ndpiPacketProcess func(gopacket.Packet, unsafe.Pointer) int32
	ndpiAllocFlow     func(gopacket.Packet) unsafe.Pointer
	ndpiFreeFlow      func(unsafe.Pointer)
}

// NDPIWrapper is the wrapper for the nDPI deep inspection library,
// providing the methods used to interface with it from go-dpi.
type NDPIWrapper struct {
	provider *NDPIWrapperProvider
}

// getPacketNdpiData is a helper that extracts the PCAP packet header and packet
// data pointer from a gopacket.Packet, as needed by nDPI.
func getPacketNdpiData(packet *gopacket.Packet) (pktHeader C.struct_pcap_pkthdr, pktDataPtr *C.u_char) {
	seconds := (*packet).Metadata().Timestamp.Second()
	capLen := (*packet).Metadata().CaptureLength
	packetLen := (*packet).Metadata().Length
	pktDataSlice := (*packet).Data()
	pktHeader.ts.tv_sec = C.__time_t(seconds)
	pktHeader.ts.tv_usec = 0
	pktHeader.caplen = C.bpf_u_int32(capLen)
	pktHeader.len = C.bpf_u_int32(packetLen)
	pktDataPtr = (*C.u_char)(unsafe.Pointer(&pktDataSlice[0]))
	return
}

// NewNDPIWrapper constructs an NDPIWrapper with the default implementation
// for its methods.
func NewNDPIWrapper() *NDPIWrapper {
	return &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return int32(C.ndpiInitialize()) },
			ndpiDestroy:    func() { C.ndpiDestroy() },
			ndpiPacketProcess: func(packet gopacket.Packet, ndpiFlow unsafe.Pointer) int32 {
				pktHeader, pktDataPtr := getPacketNdpiData(&packet)
				return int32(C.ndpiPacketProcess(&pktHeader, pktDataPtr, ndpiFlow))
			},
			ndpiAllocFlow: func(packet gopacket.Packet) unsafe.Pointer {
				pktHeader, pktDataPtr := getPacketNdpiData(&packet)
				return C.ndpiGetFlow(&pktHeader, pktDataPtr)
			},
			ndpiFreeFlow: func(ndpiFlow unsafe.Pointer) {
				C.ndpiFreeFlow(ndpiFlow)
			},
		},
	}
}

// InitializeWrapper initializes the nDPI wrapper.
func (wrapper *NDPIWrapper) InitializeWrapper() int {
	return int((*wrapper.provider).ndpiInitialize())
}

// DestroyWrapper destroys the nDPI wrapper.
func (wrapper *NDPIWrapper) DestroyWrapper() error {
	(*wrapper.provider).ndpiDestroy()
	return nil
}

// ClassifyFlow classifies a flow using the nDPI library. It returns the
// detected protocol and any error.
func (wrapper *NDPIWrapper) ClassifyFlow(flow *types.Flow) (types.Protocol, error) {
	packets := flow.GetPackets()
	if len(packets) > 0 {
		ndpiFlow := (*wrapper.provider).ndpiAllocFlow(*packets[0])
		defer (*wrapper.provider).ndpiFreeFlow(ndpiFlow)
		for _, ppacket := range packets {
			ndpiProto := (*wrapper.provider).ndpiPacketProcess(*ppacket, ndpiFlow)
			if proto, found := ndpiCodeToProtocol[uint32(ndpiProto)]; found {
				return proto, nil
			} else if ndpiProto < 0 {
				switch ndpiProto {
				case -10:
					return types.Unknown, errors.New("nDPI wrapper does not support IPv6")
				case -11:
					return types.Unknown, errors.New("Received fragmented packet")
				case -12:
					return types.Unknown, errors.New("Error creating nDPI flow")
				default:
					return types.Unknown, errors.New("nDPI unknown error")
				}
			}
		}
	}
	return types.Unknown, nil
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *NDPIWrapper) GetWrapperName() types.ClassificationSource {
	return NDPIWrapperName
}
