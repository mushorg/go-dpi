package wrappers

// #cgo CXXFLAGS: -std=c++11
// #cgo LDFLAGS: -lprotoident -ltrace
// #include "LPI_wrapper_impl.hpp"
import "C"
import (
	"github.com/mushorg/go-dpi"
	"unsafe"
)

// lpiCodeToProtocol maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToProtocol = map[uint32]godpi.Protocol{
	0:   godpi.Http,
	14:  godpi.Dns,
	201: godpi.Dns,
	8:   godpi.Ssh,
	23:  godpi.Rpc,
	1:   godpi.Smtp,
	21:  godpi.Rdp,
	24:  godpi.Smb,
	380: godpi.Icmp,
	27:  godpi.Ftp,
	12:  godpi.Ssl,
	37:  godpi.Netbios,
}

// LPIWrapper is the wrapper for the LPI protocol identification library,
// providing the methods used to interface with it from go-dpi.
type LPIWrapper struct{}

// NewLPIWrapper constructs a new LPIWrapper.
func NewLPIWrapper() *LPIWrapper {
	return &LPIWrapper{}
}

// InitializeWrapper initializes the libprotoident wrapper.
func (wrapper *LPIWrapper) InitializeWrapper() error {
	C.lpiInitLibrary()
	return nil
}

// DestroyWrapper destroys the libprotoident wrapper.
func (wrapper *LPIWrapper) DestroyWrapper() error {
	C.lpiDestroyLibrary()
	return nil
}

// ClassifyFlow classifies a flow using the libprotoident library. It returns
// the detected protocol and any error.
func (wrapper *LPIWrapper) ClassifyFlow(flow *godpi.Flow) (godpi.Protocol, error) {
	lpiFlow := C.lpiCreateFlow()
	defer C.lpiFreeFlow(lpiFlow)
	for _, packet := range flow.Packets {
		pktData := (*packet).Data()
		dataPtr := unsafe.Pointer(&pktData[0])
		C.lpiAddPacketToFlow(lpiFlow, dataPtr, C.ushort(len(pktData)))
	}
	lpiProto := uint32(C.lpiGuessProtocol(lpiFlow))
	if proto, found := lpiCodeToProtocol[lpiProto]; found {
		return proto, nil
	}
	return godpi.Unknown, nil
}
