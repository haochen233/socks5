package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Client defines parameters for running socks client.
type Client struct {
	// in the form "host:port". If empty, ":1080" (port 1080) is used.
	ProxyAddr string

	// method mapping to the authenticator
	Auth map[METHOD]interface{}

	UDPTimout  int
	TCPTimeout int

	// Generate by Server.Addr field. For Server internal use only.
	bindAddr *Address

	// ErrorLog specifics an options logger for errors accepting
	// If nil, logging is done via log package's standard logger.
	ErrorLog *log.Logger
}

// MemoryStore store username&password in memory.
// the password is encrypt with hash method.
type PwdStore struct {
	User     string
	Password string
	mu       sync.Mutex
}

// NewMemeryStore return a new MemoryStore
func NewPwdStore() *PwdStore {
	return &PwdStore{}
}

func (m *PwdStore) Set(username string, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.User = username
	m.Password = password
	return nil
}

// NewClient create a client
func NewClient(proxyAddr string, opts interface{}) *Client {
	c := &Client{
		ProxyAddr: proxyAddr,
	}
	if opts != nil {
		switch value := opts.(type) {
		case *PwdStore:
			c.Auth = map[METHOD]interface{}{USERNAME_PASSWORD: value}
		}
	}
	return c
}

func (clt *Client) Dial(request *Request) (net.Conn, error) {
	switch request.CMD {
	case BIND, CONNECT:
		return clt.DialTCP(request)
	case UDP_ASSOCIATE:
		return clt.DialUDP(request)
	default:
		return nil, errors.New("net support network")
	}
}

func (clt *Client) DialTCP(request *Request) (net.Conn, error) {
	proxyConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if _, err := clt.handShake(request, proxyConn); err != nil {
		clt.logf()(err.Error())
		proxyConn.Close()
		return nil, err
	}
	return proxyConn, nil
}

// handShake socks protocol handshake process
func (clt *Client) handShake(request *Request, proxyConn net.Conn) (string, error) {
	if request.VER == Version5 {
		err := clt.authentication(proxyConn)
		if err != nil {
			return "", err
		}
		clt.socks5Request(request, proxyConn)
	} else if request.VER == Version4 {
		clt.socks4Request(request, proxyConn)
	}

	reply, err := clt.parseReply(request, proxyConn)
	if err != nil {
		return "", err
	}
	if reply.REP != SUCCESSED {
		return "", errors.New("host unreachable")
	}
	return reply.Address.String(), nil
}

func (clt *Client) authentication(proxyConn net.Conn) error {
	var methods []byte
	methods = append(methods, NO_AUTHENTICATION_REQUIRED)
	if clt.Auth != nil {
		methods = append(methods, USERNAME_PASSWORD)
	}

	_, err := proxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return nil
	}
	reply, err := ReadNBytes(proxyConn, 2)

	if err != nil {
		return err
	}
	if reply[0] != Version5 {
		return &VersionError{reply[0]}
	}

	if (reply[1] != USERNAME_PASSWORD) && (reply[1] != NO_AUTHENTICATION_REQUIRED) {
		return &MethodError{reply[1]}
	}
	if reply[1] == USERNAME_PASSWORD {
		var user, pass string
		switch value := clt.Auth[USERNAME_PASSWORD].(type) {
		case *PwdStore:
			user = value.User
			pass = value.Password
		}
		userPassRequest := append([]byte{0x01, byte(len(user))}, []byte(user)...)
		userPassRequest = append(userPassRequest, byte(len(pass)))
		_, err = proxyConn.Write(append(userPassRequest, []byte(pass)...))
		if err != nil {
			return err
		}
		reply, err = ReadNBytes(proxyConn, 2)
		if err != nil {
			return err
		}
		if reply[0] != 0x01 {
			return errors.New("not support method")
		}
		if reply[1] != SUCCESSED {
			return fmt.Errorf("user authentication failed")
		}
	}
	return nil
}

func (clt *Client) socks5Request(request *Request, proxyConn net.Conn) (err error) {
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return err
	}
	b := []byte{request.VER, request.CMD, request.RSV}
	if _, err := proxyConn.Write(append(b, destAddrByte...)); err != nil {
		return err
	}
	return nil
}

func (clt *Client) socks4Request(request *Request, proxyConn net.Conn) (err error) {
	destAddrByte, err := request.Address.Bytes(Version4)
	if err != nil {
		return err
	}
	b := []byte{request.VER, request.CMD}
	if _, err := proxyConn.Write(append(b, destAddrByte...)); err != nil {
		return err
	}
	return nil
}

// parseReply parse to reply from io.Reader
func (clt *Client) parseReply(request *Request, r io.Reader) (rep Reply, err error) {
	if request.VER == Version4 {
		// Read the version and command
		tmp, err := ReadNBytes(r, 2)
		if err != nil {
			return rep, fmt.Errorf("failed to get reply version and command, %v", err)
		}
		rep.VER, rep.REP = tmp[0], tmp[1]
		if rep.VER != Version4 {
			return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.VER)
		}
	} else if request.VER == Version5 {
		// Read the version and command
		tmp, err := ReadNBytes(r, 3)
		if err != nil {
			return rep, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
		}
		rep.VER, rep.REP, rep.RSV = tmp[0], tmp[1], tmp[2]
		if rep.VER != Version5 {
			return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.VER)
		}
	} else {
		return rep, &VersionError{request.VER}
	}
	// Read address
	serverBoundAddr, _, err := readAddress(r, request.VER)
	if err != nil {
		return rep, fmt.Errorf("failed to get reply address, %v", err)
	}
	rep.Address = serverBoundAddr
	return rep, nil
}

func (clt *Client) DialUDP(request *Request) (net.Conn, error) {
	proxyTCPConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	bndAddress, err := clt.handShake(request, proxyTCPConn)
	if err != nil {
		return nil, err
	}
	ra, err := net.ResolveUDPAddr("udp", bndAddress)
	if err != nil {
		clt.logf()(err.Error())
		proxyTCPConn.Close()
		return nil, err
	}
	ad := proxyTCPConn.LocalAddr().(*net.TCPAddr)
	laddr := &net.UDPAddr{
		IP:   ad.IP,
		Port: ad.Port,
		Zone: ad.Zone,
	}
	proxyUDPConn, err := net.DialUDP("udp", laddr, ra)
	if err != nil {
		clt.logf()(err.Error())
		proxyTCPConn.Close()
		return nil, err
	}
	return &SocksUDPConn{
		UDPConn: proxyUDPConn,
		dstAddr: request.Address,
		timeout: time.Duration(clt.UDPTimout) * time.Second,
	}, nil
}

func (clt *Client) logf() func(format string, args ...interface{}) {
	if clt.ErrorLog == nil {
		return log.Printf
	}
	return clt.ErrorLog.Printf
}

type SocksUDPConn struct {
	*net.UDPConn
	dstAddr *Address
	timeout time.Duration
}

func (p *SocksUDPConn) Read(b []byte) (int, error) {
	if p.timeout != 0 {
		p.UDPConn.SetReadDeadline(time.Now().Add(p.timeout))
	}

	tmp, err := ReadNBytes(p.UDPConn, 3)
	if err != nil {
		return 0, err
	}
	var udpHeader UDPHeader
	udpHeader.RSV, udpHeader.FRAG = binary.BigEndian.Uint16(tmp[0:1]), tmp[2]
	addr, _, err := readAddress(p.UDPConn, Version5)
	if err != nil {
		return 0, err
	}
	udpHeader.Address = addr
	data, err := ReadUntilNULL(p.UDPConn)
	if err != nil {
		return 0, err
	}
	udpHeader.Data = data

	if len(b) < len(udpHeader.Data) {
		return 0, errors.New("buff too small")
	}
	n := copy(b, udpHeader.Data)
	return n, nil
}

func (p *SocksUDPConn) Write(b []byte) (int, error) {
	d := []byte{0, 0, 0}
	addrByets, err := p.dstAddr.Bytes(Version5)
	if err != nil {
		return 0, err
	}
	payload := append(append(d, addrByets...), b...)
	n, err := p.UDPConn.Write(payload)

	if err != nil {
		return 0, err
	}
	if len(payload) != n {
		return 0, errors.New("not write full")
	}
	return len(b), nil
}
