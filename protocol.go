package socks5

import (
	"io"
	"net"
)

// VER indicates protocol version
type VER = uint8

const (
	Version4 = 0x04
	Version5 = 0x05
)

// METHOD Defined authentication methods
type METHOD = uint8

const (
	NO_AUTHENTICATION_REQUIRED METHOD = 0x00
	GSSAPI                     METHOD = 0x01
	USERNAME_PASSWORD          METHOD = 0x02
	IANA_ASSIGNED              METHOD = 0x03
	NO_ACCEPTABLE_METHODS      METHOD = 0x05
)

// CMD is one of a field in Socks5 Request
type CMD = uint8

const (
	CONNECT       CMD = 0x01
	BIND          CMD = 0x02
	UDP_ASSOCIATE CMD = 0x03
)

// REP is one of a filed in Socks5 Reply
type REP = uint8

const (
	SUCCESSED                       REP = 0x00
	GENERAL_SOCKS_SERVER_FAILURE    REP = 0x01
	CONNECTION_NOT_ALLOW_BY_RULESET REP = 0x02
	NETWORK_UNREACHABLE             REP = 0x03
	HOST_UNREACHABLE                REP = 0x04
	CONNECTION_REFUSED              REP = 0x05
	TTL_EXPIRED                     REP = 0x06
	COMMAND_NOT_SUPPORTED           REP = 0x07
	ADDRESS_TYPE_NOT_SUPPORTED      REP = 0x08
	UNASSIGNED                      REP = 0x09
)

// ATYPE indicates adderss type in Request and Reply struct
type ATYPE = uint8

const (
	IPV4_ADDRESS ATYPE = 0x01
	DOMAINNAME   ATYPE = 0x03
	IPV6_ADDRESS ATYPE = 0x04
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
	DestAddr net.IPAddr
	DestPort uint16
}

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
	BindAddr net.IPAddr
	BindPort uint16
}

func DecodeReply(reply *Reply) ([]byte, error) {
	return nil, nil
}

type HandShake interface {
	HandShake(reader io.Reader, writer io.Writer) (*Request, error)
	handshake4(cmd CMD, reader io.Reader, writer io.Writer) (*Request, error)
	handshake5()
}

type DefaultHandShake struct{}
