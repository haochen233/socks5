package socks5

import "fmt"

type VersionError struct {
	VER
}

func (v *VersionError) Error() string {
	return fmt.Sprintf("error socks protocol version: %d", v.VER)
}

// VER indicates protocol version
type VER = uint8

const (
	Version4 = 0x04
	Version5 = 0x05
)

type MethodError struct {
	METHOD
}

func (m *MethodError) Error() string {
	if _, ok := method2Str[m.METHOD]; ok {
		return fmt.Sprintf("don't support this method %s", method2Str[m.METHOD])
	} else {
		return fmt.Sprintf("unknown mehotd %#x", m.METHOD)
	}
}

// METHOD Defined authentication methods
type METHOD = uint8

const (
	NO_AUTHENTICATION_REQUIRED METHOD = 0x00
	GSSAPI                     METHOD = 0x01
	USERNAME_PASSWORD          METHOD = 0x02
	IANA_ASSIGNED              METHOD = 0x03
	NO_ACCEPTABLE_METHODS      METHOD = 0x05
)

var method2Str = map[METHOD]string{
	NO_AUTHENTICATION_REQUIRED: "NO_AUTHENTICATION_REQUIRED",
	GSSAPI:                     "GSSAPI",
	USERNAME_PASSWORD:          "USERNAME_PASSWORD",
	IANA_ASSIGNED:              "IANA_ASSIGNED",
	NO_ACCEPTABLE_METHODS:      "NO_ACCEPTABLE_METHODS",
}

//
type CMDError struct {
	CMD
}

func (c *CMDError) Error() string {
	if _, ok := cmdtoStr[c.CMD]; !ok {
		return fmt.Sprintf("unknown command:%#x", c.CMD)
	}
	return fmt.Sprintf("don't support this command:%s", cmdtoStr[c.CMD])
}

// CMD is one of a field in Socks5 Request
type CMD = uint8

const (
	CONNECT       CMD = 0x01
	BIND          CMD = 0x02
	UDP_ASSOCIATE CMD = 0x03
)

var cmdtoStr = map[CMD]string{
	CONNECT:       "CONNECT",
	BIND:          "BIND",
	UDP_ASSOCIATE: "UDP_ASSOCIATE",
}

// REP is one of a filed in Socks5 Reply
type REP = uint8

//socks5 reply
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

var rep2Str = map[REP]string{
	SUCCESSED:                       "SUCCESSED",
	GENERAL_SOCKS_SERVER_FAILURE:    "GENERAL_SOCKS_SERVER_FAILURE",
	CONNECTION_NOT_ALLOW_BY_RULESET: "CONNECTION_NOT_ALLOW_BY_RULESET",
	NETWORK_UNREACHABLE:             "NETWORK_UNREACHABLE",
	HOST_UNREACHABLE:                "HOST_UNREACHABLE",
	CONNECTION_REFUSED:              "CONNECTION_REFUSED",
	TTL_EXPIRED:                     "TTL_EXPIRED",
	COMMAND_NOT_SUPPORTED:           "COMMAND_NOT_SUPPORTED",
	ADDRESS_TYPE_NOT_SUPPORTED:      "ADDRESS_TYPE_NOT_SUPPORTED",
	UNASSIGNED:                      "UNASSIGNED",
}

//socks4 reply
const (
	// PERMIT means server allow  client request
	PERMIT = 90
	// REJECT means server refuse client request
	REJECT = 91
)

type AtypeError struct {
	ATYPE
}

func (a *AtypeError) Error() string {
	return fmt.Sprintf("unknown address type:%#x", a.ATYPE)
}

// ATYPE indicates adderss type in Request and Reply struct
type ATYPE = uint8

const (
	IPV4_ADDRESS ATYPE = 0x01
	DOMAINNAME   ATYPE = 0x03
	IPV6_ADDRESS ATYPE = 0x04
)
