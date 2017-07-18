// Package godpi contains the basic types and methods that the library provides.
package godpi

// Protocol is the type of each of the detected protocols.
type Protocol string

const (
	HTTP    Protocol = "HTTP"
	DNS     Protocol = "DNS"
	SSH     Protocol = "SSH"
	RPC     Protocol = "RPC"
	SMTP    Protocol = "SMTP"
	RDP     Protocol = "RDP"
	SMB     Protocol = "SMB"
	ICMP    Protocol = "ICMP"
	FTP     Protocol = "FTP"
	SSL     Protocol = "SSL"
	NetBIOS Protocol = "NetBIOS"
	Unknown Protocol = ""
)
