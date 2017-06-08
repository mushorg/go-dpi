// Package godpi contains the basic types and methods that the library provides.
package godpi

// Protocol is the type of each of the detected protocols.
type Protocol string

const (
	Http    Protocol = "HTTP"
	Dns     Protocol = "DNS"
	Ssh     Protocol = "SSH"
	Rpc     Protocol = "RPC"
	Smtp    Protocol = "SMTP"
	Rdp     Protocol = "RDP"
	Smb     Protocol = "SMB"
	Icmp    Protocol = "ICMP"
	Ftp     Protocol = "FTP"
	Ssl     Protocol = "SSL"
	Netbios Protocol = "NetBIOS"
	Unknown Protocol = ""
)
