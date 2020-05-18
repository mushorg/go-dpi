package types

// Protocol is the type of each of the detected protocols.
type Protocol string

// Protocol identifiers for the supported protocols
const (
	HTTP       Protocol = "HTTP"
	DNS        Protocol = "DNS"
	SSH        Protocol = "SSH"
	RPC        Protocol = "RPC"
	SMTP       Protocol = "SMTP"
	RDP        Protocol = "RDP"
	SMB        Protocol = "SMB"
	ICMP       Protocol = "ICMP"
	FTP        Protocol = "FTP"
	SSL        Protocol = "SSL"
	NetBIOS    Protocol = "NetBIOS"
	JABBER     Protocol = "JABBER"
	MQTT       Protocol = "MQTT"
	BITTORRENT Protocol = "BitTorrent"
	Unknown    Protocol = ""
)
