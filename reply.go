package socks5

import (
	"encoding/binary"
	"errors"
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
func SerializeSocks4Reply(cmd CMD, ip net.IP, port uint16) ([]byte, error) {
	if _, ok := cmd2Str[cmd]; !ok {
		return nil, &CMDError{cmd}
	}
	reply := []byte{0, cmd}
	reply = append(reply, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	reply = append(reply, portBytes...)
	return reply, nil
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

var errDoaminMaxLengthLimit = errors.New("domain name out of max length")

// SerializeSocks5Reply serialize socks5 reply to []byte
func SerializeSocks5Reply(rep REP, atype ATYPE, addr net.IP, port uint16) ([]byte, error) {
	if _, ok := rep2Str[rep]; !ok {
		return nil, &REPError{rep}
	}
	if _, ok := atype2Str[atype]; !ok {
		return nil, &AtypeError{atype}
	}

	reply := []byte{Version5, rep, 0, atype}
	if atype == DOMAINNAME {
		if len(addr) > 255 {
			return nil, errDoaminMaxLengthLimit
		}
		reply = append(reply, byte(len(addr)))
	}
	reply = append(reply, addr...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	reply = append(reply, portBytes...)
	return reply, nil
}
