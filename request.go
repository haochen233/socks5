package socks5

import (
	"net"
	"strconv"
)

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

// Address return dest server address
// Examples:
//	127.0.0.1:80
//	example.com:443
//  [fe80::1%lo0]:80
func (r *Request) Address() string {
	if r.ATYPE == DOMAINNAME {
		return net.JoinHostPort(string(r.DestAddr), strconv.Itoa(int(r.DestPort)))
	}
	return net.JoinHostPort(r.DestAddr.String(), strconv.Itoa(int(r.DestPort)))
}
