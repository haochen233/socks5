package socks5

import (
	"errors"
	"net"
)

type Client struct {
	ProxyAddr      string
	ProxyConn      net.Conn
	Authenticators map[METHOD]Authenticator
}

// NewClient create a client
func NewClient(proxyAddr string, opts ...string) *Client {
	c := &Client{
		ProxyAddr: proxyAddr,
	}
	return c
}

func (clt *Client) Dial(network, addr string) (net.Conn, error) {
	if network == "tcp" {

	}
	if network == "udp" {

	}
	return nil, errors.New("net support network")
}

func (clt *Client) TCPDial(network, addr string) (net.Conn, error) {
	remoteAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	clt.ProxyConn, err = net.Dial(network, clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if _, err := clt.HandShake(CONNECT, addr); err != nil {
		return nil, err
	}
}

func (clt *Client) HandShake(command CMD, addr string) (string, error) {
	var methods []byte
	//methods := NO_AUTHENTICATION_REQUIRED
	if clt.Authenticators != nil {
		methods = append(methods, USERNAME_PASSWORD)
	}
	//_, err := clt.ProxyConn.Write(NewMethodRequest(Version5, []byte{methods}).Bytes())
	_, err := clt.ProxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return "", nil
	}
	reply, err := ReadNBytes(clt.ProxyConn, 2)

	//reply, err := ParseMethodReply(clt.ProxyConn)
	if err != nil {
		return "", err
	}
	if reply[0] != Version5 {
		return "", &VersionError{reply[0]}
	}

	if (reply[1] != USERNAME_PASSWORD) && (reply[1] != NO_AUTHENTICATION_REQUIRED) {
		return "", &MethodError{reply[1]}
	}
	if reply[1] == USERNAME_PASSWORD {
		//_, err = clt.ProxyConn.Write([]byte(0x01, byte(len(user)), byte(len(pass)), user, pass))
		//_, err = clt.ProxyConn.Write(NewUserPassRequest(byte(0x01), []byte(clt.Authenticators[USERNAME_PASSWORD])))
	}
	
}

type UserPassRequest struct {
	VER
	Ulen uint8
	Plen uint8
	User []byte
	Pass []byte
}

func NewUserPassRequest(ver VER, user, pass []byte) UserPassRequest {
	return UserPassRequest{
		ver,
		byte(len(user)),
		byte(len(pass)),
		user,
		pass,
	}
}
