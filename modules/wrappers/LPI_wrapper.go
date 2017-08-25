package wrappers

// #include "wrappers_config.h"
// #ifndef DISABLE_LPI
// #cgo CXXFLAGS: -std=c++11
// #cgo LDFLAGS: -L/usr/lib -L/usr/local/lib -L${SRCDIR} -Wl,-Bdynamic -lprotoident -ltrace
// #endif
// #include "LPI_wrapper_impl.hpp"
import "C"
import (
	"unsafe"

	"github.com/mushorg/go-dpi/types"
)

// lpiCodeToProtocol maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToProtocol = map[uint32]types.Protocol{
	0:   types.HTTP,    // LPI_PROTO_HTTP
	14:  types.DNS,     // LPI_PROTO_DNS
	201: types.DNS,     // LPI_PROTO_UDP_DNS
	8:   types.SSH,     // LPI_PROTO_SSH
	23:  types.RPC,     // LPI_PROTO_RPC_SCAN
	1:   types.SMTP,    // LPI_PROTO_SMTP
	92:  types.SMTP,    // LPI_PROTO_INVALID_SMTP
	21:  types.RDP,     // LPI_PROTO_RDP
	24:  types.SMB,     // LPI_PROTO_SMB
	380: types.ICMP,    // LPI_PROTO_ICMP
	27:  types.FTP,     // LPI_PROTO_FTP_CONTROL
	12:  types.SSL,     // LPI_PROTO_SSL
	37:  types.NetBIOS, // LPI_PROTO_NETBIOS
}

// LPIWrapperName is the identification of the libprotoident library.
const LPIWrapperName = "libprotoident"

// LPIWrapper is the wrapper for the LPI protocol identification library,
// providing the methods used to interface with it from go-dpi.
type LPIWrapper struct{}

// NewLPIWrapper constructs a new LPIWrapper.
func NewLPIWrapper() *LPIWrapper {
	return &LPIWrapper{}
}

// InitializeWrapper initializes the libprotoident wrapper.
func (wrapper *LPIWrapper) InitializeWrapper() int {
	return int(C.lpiInitLibrary())
}

// DestroyWrapper destroys the libprotoident wrapper.
func (wrapper *LPIWrapper) DestroyWrapper() error {
	C.lpiDestroyLibrary()
	return nil
}

// ClassifyFlow classifies a flow using the libprotoident library. It returns
// the detected protocol and any error.
func (wrapper *LPIWrapper) ClassifyFlow(flow *types.Flow) (types.Protocol, error) {
	lpiFlow := C.lpiCreateFlow()
	defer C.lpiFreeFlow(lpiFlow)
	for _, packet := range flow.GetPackets() {
		pktData := (*packet).Data()
		dataPtr := unsafe.Pointer(&pktData[0])
		C.lpiAddPacketToFlow(lpiFlow, dataPtr, C.ushort(len(pktData)))
	}
	lpiProto := uint32(C.lpiGuessProtocol(lpiFlow))
	if proto, found := lpiCodeToProtocol[lpiProto]; found {
		return proto, nil
	}
	return types.Unknown, nil
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *LPIWrapper) GetWrapperName() types.ClassificationSource {
	return LPIWrapperName
}
