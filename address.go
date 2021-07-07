package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
)

type Address struct {
	Addr net.IP
	ATYPE
	Port uint16
}

var bufPool = sync.Pool{New: func() interface{} {
	buf := bytes.Buffer{}
	return &buf
}}

// Address return address
// Examples:
//    127.0.0.1:80
//    example.com:443
//    [fe80::1%lo0]:80
func (a *Address) String() string {
	if a.ATYPE == DOMAINNAME {
		return net.JoinHostPort(string(a.Addr), strconv.Itoa(int(a.Port)))
	}
	return net.JoinHostPort(a.Addr.String(), strconv.Itoa(int(a.Port)))
}

var errDoaminMaxLengthLimit = errors.New("domain name out of max length")

// Bytes return bytes slice of Address by ver param.
// if ver is socks4, the returned socks4 address format as follows:
//    +----+----+----+----+----+----+....+----+....+----+
//    | DSTPORT |      DSTIP        | USERID       |NULL|
//    +----+----+----+----+----+----+----+----+....+----+
// if ver is socks4 and address type is domain name,
// the returned socks4 address format as follows:
//    +----+----+----+----+----+----+....+----+....+----+....+----+....+----+
//    | DSTPORT |      DSTIP        | USERID       |NULL|   HOSTNAME   |NULL|
//    +----+----+----+----+----+----+----+----+....+----+----+----+....+----+
// if ver is socks5
// the returned socks5 address format as follows:
//    +------+----------+----------+
//    | ATYP | DST.ADDR | DST.PORT |
//    +------+----------+----------+
//    |  1   | Variable |    2     |
//    +------+----------+----------+
func (a *Address) Bytes(ver VER) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer buf.Reset()
	defer bufPool.Put(buf)

	// port
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, a.Port)

	switch ver {
	case Version4:
		// socks4a
		if a.ATYPE == DOMAINNAME {
			buf.Write(net.IPv4(0, 0, 0, 1))
			// NULL
			buf.WriteByte(0)
			// hostname
			buf.Write(a.Addr)
			buf.WriteByte(0)
		} else if a.ATYPE == IPV4_ADDRESS {
			buf.Write(a.Addr)
		} else {
			return nil, &AtypeError{a.ATYPE}
		}
		buf.Write(port)
	case Version5:
		// address type
		buf.WriteByte(a.ATYPE)
		// domain name address type
		if a.ATYPE == DOMAINNAME {
			if len(a.Addr) > 255 {
				return nil, errDoaminMaxLengthLimit
			}
			buf.WriteByte(byte(len(a.Addr)))
		}
		buf.Write(a.Addr)
		buf.Write(port)
	}

	return buf.Bytes(), nil
}

// readAddress read address info from follows:
//    socks5 server's request.
//    socks5 client's reply.
//    socks5 server's udp reply header.
//    socks5 client's udp request header.
//
//    socks4 server's  reply.
//    socks4 client's  request.
//    socks4a server's  reply.
//    socks4a client's  request
func readAddress(r net.Conn, ver VER) (*Address, REP, error) {
	addr := &Address{}

	switch ver {
	case Version4:
		// DST.PORT
		port, err := ReadNBytes(r, 2)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version5, "read", nil, "client dest port", err}
		}
		addr.Port = binary.BigEndian.Uint16(port)
		// DST.IP
		ip, err := ReadNBytes(r, 4)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version4, "read", r.RemoteAddr(), "\"process request dest ip\"", err}
		}

		//Discard later bytes until read EOF
		//Please see socks4 request format at(http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol)
		_, err = ReadUntilNULL(r)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version4, "read", r.RemoteAddr(), "\"process request useless header \"", err}
		}

		//Socks4a extension
		//    +----+----+----+----+----+----+----+----+----+----++----++-----+-----++----+
		//    | VN | CD | DSTPORT |      DSTIP        | USERID   |NULL|  HOSTNAME   |NULL|
		//    +----+----+----+----+----+----+----+----+----+----++----++-----+-----++----+
		//       1    1      2              4           variable    1    variable    1
		//The client sets the first three bytes of DSTIP to NULL and
		//the last byte to non-zero. The corresponding IP address is
		//0.0.0.x, where x is non-zero
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 &&
			ip[3] != 0 {
			ip, err = ReadUntilNULL(r)
			if err != nil {
				return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version4, "read", r.RemoteAddr(), "\"process socks4a extension request\"", err}
			}
			addr.ATYPE = DOMAINNAME
		}
		addr.Addr = ip
	case Version5:
		// ATYP
		aType, err := ReadNBytes(r, 1)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version5, "read", nil, "dest address type", err}
		}
		addr.ATYPE = aType[0]

		var addrLen int
		switch addr.ATYPE {
		case IPV4_ADDRESS:
			addrLen = 4
		case IPV6_ADDRESS:
			addrLen = 16
		case DOMAINNAME:
			fqdnLength, err := ReadNBytes(r, 1)
			if err != nil {
				return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version5, "read", nil, "\"dest domain name length\"", err}
			}
			addrLen = int(fqdnLength[0])
		default:
			return nil, ADDRESS_TYPE_NOT_SUPPORTED, &OpError{Version5, "", nil, "\"dest address\"", &AtypeError{aType[0]}}
		}

		// DST.ADDR
		ip, err := ReadNBytes(r, addrLen)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, err
		}
		addr.Addr = ip

		// DST.PORT
		port, err := ReadNBytes(r, 2)
		if err != nil {
			return nil, GENERAL_SOCKS_SERVER_FAILURE, &OpError{Version5, "read", nil, "client dest port", err}
		}
		addr.Port = binary.BigEndian.Uint16(port)
	}

	return addr, SUCCESSED, nil
}
