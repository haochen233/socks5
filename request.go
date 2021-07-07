package socks5

import (
	"net"
)

// Request The SOCKS request is formed as follows:
//    +----+-----+-------+------+----------+----------+
//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//    +----+-----+-------+------+----------+----------+
//    | 1  |  1  | X'00' |  1   | Variable |    2     |
//    +----+-----+-------+------+----------+----------+
type Request struct {
	VER
	CMD
	RSV uint8
	ATYPE
	DestAddr net.IP
	DestPort uint16
	*Address
}

// UDPHeader Each UDP datagram carries a UDP request
// header with it:
//    +----+------+------+----------+----------+----------+
//    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//    +----+------+------+----------+----------+----------+
//    | 2  |  1   |  1   | Variable |    2     | Variable |
//    +----+------+------+----------+----------+----------+
type UDPHeader struct {
	RSV  uint16
	FRAG uint8
	ATYPE
	DestAddr net.IP
	DestPort uint16
	Data     []byte
}
