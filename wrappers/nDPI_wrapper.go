package wrappers

// #cgo CFLAGS: -I/usr/local/include/
// #cgo LDFLAGS: /usr/local/lib/libndpi.a -lpcap -lm -pthread
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"unsafe"

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
	ndpiPacketProcess func(int, int, int, []byte) int32
}

// NDPIWrapper is the wrapper for the nDPI deep inspection library,
// providing the methods used to interface with it from go-dpi.
type NDPIWrapper struct {
	provider *NDPIWrapperProvider
}

// NewNDPIWrapper constructs an NDPIWrapper with the default implementation
// for its methods.
func NewNDPIWrapper() *NDPIWrapper {
	return &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return int32(C.ndpiInitialize()) },
			ndpiDestroy:    func() { C.ndpiDestroy() },
			ndpiPacketProcess: func(seconds, capLen, packetLen int, pktData []byte) int32 {
				var pktHeader C.struct_pcap_pkthdr
				pktHeader.ts.tv_sec = C.__time_t(seconds)
				pktHeader.ts.tv_usec = 0
				pktHeader.caplen = C.bpf_u_int32(capLen)
				pktHeader.len = C.bpf_u_int32(packetLen)
				pktDataPtr := unsafe.Pointer(&pktData[0])
				return int32(C.ndpiPacketProcess(&pktHeader, (*C.u_char)(pktDataPtr)))
			},
		},
	}
}

// InitializeWrapper initializes the nDPI wrapper.
func (wrapper *NDPIWrapper) InitializeWrapper() error {
	if (*wrapper.provider).ndpiInitialize() != 0 {
		return errors.New("nDPI global structure initialization failed")
	}
	return nil
}

// DestroyWrapper destroys the nDPI wrapper.
func (wrapper *NDPIWrapper) DestroyWrapper() error {
	(*wrapper.provider).ndpiDestroy()
	return nil
}

// ClassifyFlow classifies a flow using the nDPI library. It returns the
// detected protocol and any error.
func (wrapper *NDPIWrapper) ClassifyFlow(flow *types.Flow) (types.Protocol, error) {
	for _, ppacket := range flow.Packets {
		packet := *ppacket
		seconds := packet.Metadata().Timestamp.Second()
		capLen := packet.Metadata().CaptureLength
		packetLen := packet.Metadata().Length
		pktDataSlice := packet.Data()
		ndpiProto := (*wrapper.provider).ndpiPacketProcess(seconds, capLen, packetLen, pktDataSlice)
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
	return types.Unknown, nil
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *NDPIWrapper) GetWrapperName() types.ClassificationSource {
	return NDPIWrapperName
}
