package socks5

import "net"

// Request The SOCKS request is formed as follows:
//
//        +----+-----+-------+------+----------+----------+
//        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//        +----+-----+-------+------+----------+----------+
//        | 1  |  1  | X'00' |  1   | Variable |    2     |
//        +----+-----+-------+------+----------+----------+
type Request struct {
	VER
	CMD
	RSV uint8
	ATYPE
	DestAddr net.IP
	DestPort uint16
}
