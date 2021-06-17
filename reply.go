package socks5

import (
	"encoding/binary"
	"net"
)

// Reply a reply formed as follows:
//
//        +----+-----+-------+------+----------+----------+
//        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//        +----+-----+-------+------+----------+----------+
//        | 1  |  1  | X'00' |  1   | Variable |    2     |
//        +----+-----+-------+------+----------+----------+
type Reply struct {
	VER
	REP
	RSV uint8
	ATYPE
	BindAddr net.IP
	BindPort uint16
}

// SerializeSocks4Reply serialize socks4 reply to []byte
func SerializeSocks4Reply(cmd CMD, ip net.IP, port uint16) []byte {
	reply := []byte{0, cmd}
	reply = append(reply, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	reply = append(reply, portBytes...)
	return reply
}

// DeserializeSocks4Reply deserialize socks4 []byte to reply
func DeserializeSocks4Reply(b []byte) (*Reply, error) {
	reply := &Reply{
		VER:      b[0],
		REP:      b[1],
		BindAddr: b[2:6],
		BindPort: binary.BigEndian.Uint16(b[6:]),
	}
	return reply, nil
}

// SerializeSocks5Reply serialize socks5 reply to []byte
func SerializeSocks5Reply() []byte {
	return nil
}
